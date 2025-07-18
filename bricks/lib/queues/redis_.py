# -*- coding: utf-8 -*-
# @Time    : 2023-12-11 13:14
# @Author  : Kem
# @Desc    :
import datetime
import json
import threading
import time

from loguru import logger

from bricks import state
from bricks.db.redis_ import LUA, Redis
from bricks.lib.queues import TaskQueue
from bricks.utils import pandora


class RedisQueue(TaskQueue):
    subscribe = True

    def __init__(
            self,
            host="127.0.0.1",
            password=None,
            port=6379,
            database=0,
            genre="set",
            **kwargs,
    ):
        self.redis_db = Redis(
            host=host, password=password, port=port, database=database, **kwargs
        )
        self.host = host
        self.database = database
        self.genre = genre
        self.lua = LUA(self.redis_db)

        class Scripts:
            get = self.lua.register("""
    local db_num = KEYS[1]
    local key = KEYS[2]
    local count = KEYS[3]
    local default_type = KEYS[4]
    local backup_key = KEYS[5]
    changeDataBase(db_num)
    return popItems(key, count, default_type, backup_key)   
                    """)
            put = self.lua.register("""
    local db_num = KEYS[1]
    local default_type = KEYS[2]
    local values = ARGV

    changeDataBase(db_num)
    local success = 0
    for i = 3, #KEYS do
        local key = KEYS[i]
        success = success + addItems(key, values, default_type)
    end
    return success
                    """)
            replace = self.lua.register("""
    local db_num = KEYS[1]
    local default_type = KEYS[2]
    changeDataBase(db_num)
    local ret = 0
    for i = 3, #KEYS do
        for j = 1, #ARGV, 2 do
            ret = ret + replaceItem(KEYS[i], ARGV[j], ARGV[j + 1], default_type)
        end
    end
    return ret
                    """)
            remove = self.lua.register("""
    local db_num = KEYS[1]
    local default_type = KEYS[2]
    local backup_key = KEYS[3]
    local values = ARGV
    changeDataBase(db_num)
    local ret = 0
    for i = 3, #KEYS do
        ret = ret + removeItems(KEYS[i], values, default_type, backup_key)
    end
    return ret
                    """)
            delete = self.lua.register("""
    local db_num = KEYS[1]
    local keys = ARGV
    changeDataBase(db_num)
    return redis.call("DEL", unpack(keys))
                    """)
            count = self.lua.register("""
    local db_num = KEYS[1]
    local default_type = KEYS[2]
    local keys = ARGV
    local count = 0
    changeDataBase(db_num)
    for i = 1, #keys do
        count = count + getKeySize(keys[i], default_type)
    end
    return count
                    """)
            reverse = self.lua.register("""
    local db_num = KEYS[1]
    local default_type = KEYS[2]
    local dest = KEYS[3]
    local froms = ARGV
    changeDataBase(db_num)
    return mergeKeys(dest, froms, default_type)
                    """)
            smart_reverse = self.lua.register("""
    local db_num = KEYS[1]
    local default_type = KEYS[2]

    local current_key = KEYS[3]
    local temp_key = KEYS[4]
    local failure_key = KEYS[5]
    local report_key = KEYS[6]

    changeDataBase(db_num)
    -- 设置初拾变量 running
    local running = 0
    local clients = redis.call("HGETALL", report_key)

    -- 将所有客户端上报上来的正在运行的线程数相加得到集群总运行的任务数量
    for flag = 1, #clients, 2 do
        local c = clients[flag + 1]
        running = running + tonumber(c)
        redis.call("HDEL", report_key, clients[flag])
    end
    
    -- failure 有值 -> 将 failure 放入 current
    if getKeySize(failure_key) >0 then
        mergeKeys(current_key, {failure_key}, default_type)
        return 1
    end

    -- 判断 running 是否大于 0
    if running > 0 then
        return 'running > 0'
    end

    -- failure 无值, temp 有值 -> 将 temp 放入 current
    if getKeySize(temp_key) >0 then
        mergeKeys(current_key, {temp_key}, default_type)
        return 1
    else
        return 'temp.size <=0'
    end
                    """)
            get_permission = self.lua.register("""
    -- get_permission
    local db_num = KEYS[1]
    local current_key = KEYS[2]
    local temp_key = KEYS[3]
    local failure_key = KEYS[4]
    local record_key = KEYS[5]
    local heartbeat_key = KEYS[6]
    local date_str = KEYS[7]
    local interval = KEYS[8]
    local default_type = KEYS[9]

    changeDataBase(db_num)
        
    -- 获取队列种子数量
    local queue_size = getKeySize(current_key, default_type) + getKeySize(failure_key, default_type) + getKeySize(temp_key, default_type)
    local is_record_key_exists = redis.call("EXISTS", record_key)
    -- 获取投放状态
    local status = '0'
    if is_record_key_exists == 1 then
        status = redis.call("HGET", record_key, "status")
    end

    if status ~= '1' and queue_size > 0 then
        return "已投完且存在种子没有消费完毕"
        
    else
        -- 先拿锁, 拿不到了就返回没有权限
        local ok = redis.call("SETNX", heartbeat_key, date_str)
        if ok ~= 1 then
           return "获取心跳锁失败"
        end
        -- 拿到了锁
        -- 设置过期时间
        redis.call("EXPIRE", heartbeat_key, interval)
        return "成功获取权限"
    end
                    """)
            release_init = self.lua.register("""
    local record_key = KEYS[1]
    local history_key = KEYS[2]
    local db_num = KEYS[3]
    local machine_id = KEYS[4]
    local history_ttl = tonumber(KEYS[5])
    local record_ttl = tonumber(KEYS[6])

    changeDataBase(db_num)
    redis.call("HSET", record_key, "status", 0)
    redis.call("HSET", record_key, "stop_heartbeat", 1)
    redis.call("DEL", history_key)
    local dump = redis.call('DUMP', record_key)
    
    if history_ttl ~= 0 then
        if history_ttl < 0 then
            history_ttl = 0
        end
        
        redis.call('RESTORE', history_key, history_ttl, dump)
        
    else
       redis.call('DEL', history_key)
    end
    
    if record_ttl >= 0 then
        redis.call('EXPIRE', record_key, record_ttl)
    end 
    
    return record_ttl
                    """)

            continue_init_heartbeat = self.lua.register("""
    local record_key = KEYS[1]
    local heartbeat_key = KEYS[2]
    local interval = KEYS[3]
    local stop_heartbeat = redis.call("HGET", record_key, "stop_heartbeat")
    if stop_heartbeat == "1" then
        redis.call("HDEL", record_key, "stop_heartbeat")
        return false
    end
    redis.call("SETEX", heartbeat_key, interval, redis.call("TIME")[1])
    return true
            """)

        self.scripts = Scripts

    def get(self, name, count: int = 1, **kwargs):
        """
        从 `name` 中获取种子

        :param count:
        :param name:
        :param kwargs:
        :return:
        """

        pop_key = self.name2key(name, "current")
        add_key = self.name2key(name, "temp")
        db_num = kwargs.get("db_num", self.database)
        genre = kwargs.get("genre", self.genre)
        keys = [db_num, pop_key, count or 1, genre, add_key]
        return self.scripts.get(keys=keys)

    def put(self, name, *values, **kwargs):
        """
        投放种子至 `name`

        :param name:
        :param values:
        :param kwargs:
        :return:
        """
        db_num = kwargs.get("db_num", self.database)
        genre = kwargs.get("genre", self.genre)
        qtypes = kwargs.get("qtypes", ["current"])

        if not name or not values:
            return 0

        values = self.py2str(*values)
        keys = [
            db_num,
            genre,
            *[self.name2key(name, qtype) for qtype in pandora.iterable(qtypes)],
        ]
        args = [*values]
        count = self.scripts.put(keys=keys, args=args)
        return count

    def replace(self, name, *values, **kwargs):
        """
        将 values 里面的 old 替换为 new
        values = (old, new), (old, new), (old, new)

        :param name: 队列名称

        :return:
        """
        if not name or not values:
            return 0

        db_num = kwargs.get("db_num", self.database)
        genre = kwargs.get("genre", self.genre)
        qtypes = kwargs.get("qtypes", ["current", "temp", "failure"])

        keys = [
            db_num,
            genre,
            *[self.name2key(name, qtype) for qtype in pandora.iterable(qtypes)],
        ]
        args = [j for i in values for j in self.py2str(*i)]
        return self.scripts.replace(keys=keys, args=args)

    def remove(self, name, *values, **kwargs):
        """
        从 `name` 中移除 `values`

        :param name:
        :param values:
        :return:
        """
        if not name or not values:
            return 0

        backup = kwargs.get("backup", "")
        if backup:
            backup = self.name2key(name, backup)

        db_num = kwargs.get("db_num", self.database)
        genre = kwargs.get("genre", self.genre)
        qtypes = kwargs.get("qtypes", ["temp"])
        keys = [
            db_num,
            genre,
            backup,
            *[self.name2key(name, qtype) for qtype in pandora.iterable(qtypes)],
        ]
        args = self.py2str(*values)
        return self.scripts.remove(keys=keys, args=args)

    def clear(
            self, *names, qtypes=("current", "temp", "lock", "record", "failure"), **kwargs
    ):
        db_num = kwargs.pop("db_num", self.database)
        keys = [db_num]
        args = [
            self.name2key(name, qtype)
            for name in names
            for qtype in pandora.iterable(qtypes)
        ]
        return self.scripts.delete(keys=keys, args=args)

    def size(self, *names, qtypes=("current", "temp", "failure"), **kwargs):
        """
        获取 `names` 的队列大小

        :param qtypes:
        :param names:
        :return:
        """
        if not names:
            return 0

        db_num = kwargs.pop("db_num", self.database)
        genre = kwargs.get("genre", self.genre)
        keys = [db_num, genre]
        args = [
            self.name2key(name, _) for name in names for _ in pandora.iterable(qtypes)
        ]
        return self.scripts.count(keys=keys, args=args)

    def reverse(self, name, **kwargs):
        """
        队列翻转

        :param name:
        :return:
        """
        if not name:
            return 0

        db_num = kwargs.pop("db_num", self.database)
        qtypes = kwargs.pop("qtypes", ["temp", "failure"])
        genre = kwargs.get("genre", self.genre)
        dest = self.name2key(name, "current")
        args = [self.name2key(name, qtype) for qtype in pandora.iterable(qtypes)]
        return self.merge(dest, *args, db_num=db_num, genre=genre)

    def merge(self, dest, *queues, **kwargs):
        """
        队列合并

        :param dest:
        :param queues:
        :return:
        """
        if not dest or not queues:
            return 0

        db_num = kwargs.pop("db_num", self.database)
        genre = kwargs.get("genre", self.genre)
        keys = [db_num, genre, dest]
        args = queues
        return self.scripts.reverse(keys=keys, args=args)

    def smart_reverse(self, name, timeout=1, **kwargs):
        """
        智能翻转队列
        翻转队列的条件是:
        1. failure 有值 -> 将 failure 放入 current
        2. failure 无值, temp 有值, running == 0 -> 将 temp 放入 current

        :param name:
        :param timeout:
        :return:
        """

        # 告诉其他机器开始上报状态
        self.publish(
            chanel=f"{name}-subscribe",
            msg={"action": "collect-status", "key": self.name2key(name, "report")},
            timeout=timeout,
        )

        db_num = kwargs.pop("db_num", self.database)
        genre = kwargs.get("genre", self.genre)
        keys = [
            db_num,
            genre,
            *[
                self.name2key(name, qtype)
                for qtype in ["current", "temp", "failure", "report"]
            ],
        ]
        ret = self.scripts.smart_reverse(keys=keys)
        return ret == 1

    def publish(self, chanel: str, msg: dict, timeout=0):
        # 告诉其他机器开始上报状态
        self.redis_db.publish(chanel, json.dumps(msg))
        # 等待回复
        timeout and time.sleep(timeout)

    def is_empty(self, name, threshold=0, **kwargs):
        """
        判断 `name` 是否为空

        :param threshold:
        :param name:
        :return:
        """
        return self.size(name) <= threshold

    @classmethod
    def from_redis(cls, obj, **kwargs):
        connection_kwargs: dict = obj.connection_pool.connection_kwargs
        params = dict(
            host=connection_kwargs.get("host", "127.0.0.1"),
            password=connection_kwargs.get("password"),
            port=connection_kwargs.get("port", 6379),
            database=connection_kwargs.get("db", 0),
        )
        params.update(**kwargs)
        return cls(**params)

    def command(self, name: str, order: dict):
        def run_subscribe(chanel, adapters: dict):
            """
            订阅消息
            """

            def main(message):
                msg: dict = json.loads(message["data"])
                _action = msg["action"]
                recv: str = msg.get("recv", state.MACHINE_ID)
                if recv != state.MACHINE_ID:
                    return

                if _action in adapters:
                    func = adapters[_action]
                    ret = pandora.invoke(func, args=[msg], kwargs={"queue": self})
                    key = msg["key"]
                    self.redis_db.hset(key, mapping={state.MACHINE_ID: ret})
                    self.redis_db.expire(key, 5)

            pubsub = self.redis_db.pubsub()
            pubsub.subscribe(**{chanel: main})
            return pubsub.run_in_thread(sleep_time=0.001, daemon=True)

        def get_permission():
            """
            判断是否有初始化权限
            判断依据:
                1. 已投完且存在种子没有消费完毕 -> false
                2. 成功获取权限 -> true
                3. 获取心跳锁失败
                    3.1 检测心跳锁的内容
                        3.1.1 在变化 -> false
                        3.1.2 变为空了/ 没有变化, 重新所有流程


            :return:
            :rtype:
            """

            def heartbeat():
                _keys = [
                    self.name2key(name, "record"),
                    heartbeat_key,
                    interval
                ]
                while True:
                    try:
                        if not self.scripts.continue_init_heartbeat(keys=_keys):
                            break
                        time.sleep(interval - 1)
                    except (KeyboardInterrupt, SystemExit):
                        raise

                    except Exception as e:
                        logger.error(f"[heartbeat] {e}")
                        time.sleep(1)

            db_num = order.get("db_num", self.database)
            genre = order.get("genre", self.genre)
            interval = order.get("interval", 5)

            heartbeat_key = self.name2key(name, "heartbeat")
            keys = [
                db_num,
                *[
                    self.name2key(name, i)
                    for i in ["current", "temp", "failure", "record"]
                ],
                heartbeat_key,
                str(datetime.datetime.now()),
                interval,
                genre,
            ]

            while True:
                try:
                    msg = self.scripts.get_permission(keys=keys)
                    start_time = time.time()

                    if msg == "成功获取权限":
                        # 拿到了权限, 开启心跳任务, 去更新 heartbeat 锁的时间
                        threading.Thread(target=heartbeat, daemon=True).start()
                        return {"state": True, "msg": msg}

                    elif msg == "已投完且存在种子没有消费完毕":
                        return {"state": False, "msg": msg}

                    else:  # 获取心跳锁失败
                        last = ""
                        while time.time() - start_time < interval * 3:  # 判断 interval*3 秒
                            heartbeat_value = self.redis_db.get(heartbeat_key)
                            # 锁变为空了, 重新开始所有流程
                            if heartbeat_value == "":
                                break

                            # 锁的内容在变化, 有人在操作, 直接返回
                            if last and last != heartbeat_value:  # 只要在变化, 就不嘻嘻
                                return {"state": False, "msg": "存在其他活跃的初始化机器"}

                            last = heartbeat_value
                            time.sleep(1)

                        # 锁没动过, 也重新开始所有流程
                except Exception as permission_e:
                    logger.error(f"[get_permission] {permission_e}")
                    time.sleep(30)

        def set_record():
            self.redis_db.hset(
                self.name2key(name, "record"),
                mapping=json.loads(json.dumps(order["record"], default=str)),
            )

        def wait_init():
            key = self.name2key(name, "record")
            # 爬虫的启动时间
            t1 = order.get("time")

            while True:
                # 如果队列不为空 -> 不需要等待初始化
                if not self.is_empty(name):
                    return

                # 初始化爬虫设置的开始初始化时间
                t2 = self.redis_db.hget(key, "time")
                # 当前初始化状态: 1 为开始, 0 为未开始 / 结束
                status = int(self.redis_db.hget(key, "status") or "0")
                if status == 1:
                    return

                # 初始化时间大于启动的时间
                if t2 and float(t2) >= t1:
                    return

                logger.debug("等待初始化开始")
                time.sleep(1)

        def set_init():
            key = self.name2key(name, "record")
            self.redis_db.hset(
                key, mapping={"time": int(time.time() * 1000), "status": 1}
            )

        def is_init():
            key = self.name2key(name, "record")
            # 队列不为空 -> true
            if not self.is_empty(name):
                return True

            # record 存在, 并且 status 为 1 -> true
            if self.redis_db.exists(key) and self.redis_db.hget(key, "status") == "1":
                return True

            return False

        def release_init():
            key = self.name2key(name, "record")
            history = self.name2key(name, "history")
            db_num = order.get("db_num", self.database)
            history_ttl = order.get("history_ttl") or 0
            record_ttl = order.get("record_ttl") or 0

            ret = self.scripts.release_init(
                keys=[key, history, db_num, state.MACHINE_ID, history_ttl * 1000, record_ttl]
            )
            return bool(ret)

        def get_record():
            key = self.name2key(name, "record")
            record = self.redis_db.hgetall(key) or {}
            if record.get("status") == "0":
                self.redis_db.delete(key)
                return {}
            else:
                return record

        actions = {
            self.COMMANDS.RUN_SUBSCRIBE: lambda: run_subscribe(
                f"{name}-subscribe", order["target"]
            ),
            self.COMMANDS.GET_PERMISSION: get_permission,
            self.COMMANDS.GET_RECORD: get_record,
            self.COMMANDS.CONTINUE_RECORD: lambda: self.reverse(name),
            self.COMMANDS.SET_RECORD: set_record,
            self.COMMANDS.WAIT_INIT: wait_init,
            self.COMMANDS.RESET_INIT: lambda: self.clear(name),
            self.COMMANDS.RELEASE_INIT: release_init,
            self.COMMANDS.IS_INIT: is_init,
            self.COMMANDS.SET_INIT: set_init,
        }
        action = order["action"]
        if action in actions:
            return actions[action]()

    def __str__(self):
        return f"<RedisQueue [ HOST: {self.host} | DB: {self.database} ]>"


if __name__ == "__main__":
    q = RedisQueue(genre="zset")
    print(q.put("xxx", "dasdasd4564646"))
    # print(q.replace('xxx', ({"name": "kemxxxx"}, {"name": "kem"})))
    # print(q.remove('xxx', *({"name": "kem"}, {"name": "xxx"}), qtypes=["current"]))
    # print(q.clear('xxx'))
