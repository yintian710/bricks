# -*- coding: utf-8 -*-
# @Time    : 2023-12-05 20:18
# @Author  : Kem
# @Desc    :

import inspect
from dataclasses import dataclass, field
from typing import Optional, List, Dict

from bricks import Request, Response
from bricks.lib.items import Items
from bricks.lib.queues import Item
from bricks.spider import air, form
from bricks.utils import pandora

Task = form.Task
Parse = form.Parse
Pipeline = form.Pipeline
Init = form.Init
Download = air.Download
Context = air.Context


@dataclass
class Config:
    init: Optional[List[Init]] = field(default_factory=lambda: [])
    events: Optional[Dict[str, List[Task]]] = field(default_factory=lambda: {})
    download: List[Download] = field(default_factory=lambda: [])
    parse: List[Parse] = field(default_factory=lambda: [])
    pipeline: List[Pipeline] = field(default_factory=lambda: [])


class Spider(air.Spider):

    @property
    def config(self) -> Config:
        raise NotImplementedError

    def make_seeds(self, context: air.Context, **kwargs):
        if not self.config.init:
            return

        for node in pandora.iterable(self.config.init):
            engine = node.func
            args = node.args or []
            kwargs = node.kwargs or {}
            # todo: 暂时没有内置引擎, 后面需要加几个常用的
            if str(engine).lower() in []:
                pass

            else:
                if not callable(engine):
                    engine = pandora.load_objects(engine)

                seeds = pandora.invoke(
                    func=engine,
                    args=[context, *args],
                    kwargs=kwargs,
                    annotations={air.Context: context},
                    namespace={"context": context}
                )

                if inspect.isgenerator(seeds):
                    for seed in seeds:
                        yield seed
                else:
                    yield seeds or []

    def make_request(self, context: air.Context) -> Request:
        signpost: int = context.seeds.get('$config', 0)
        configs = pandora.iterable(self.config.download)
        node: Download = configs[signpost % len(configs)]
        s = node.render(context.seeds)
        request = s.to_request()
        return request

    def parse(self, context: air.Context):
        signpost: int = context.seeds.get('$config', 0)
        configs = pandora.iterable(self.config.parse)
        node: Parse = configs[signpost % len(configs)]
        engine = node.func
        args = node.args or []
        kwargs = node.kwargs or {}

        if str(engine).lower() in ["json", "xpath", "jsonpath", "regex"]:
            items = pandora.invoke(
                func=context.response.extract,
                args=[engine.lower(), *args],
                kwargs=kwargs,
                annotations={
                    air.Context: context,
                    Response: context.response,
                    Request: context.request,
                    Item: context.seeds
                },
                namespace={
                    "context": context,
                    "response": context.response,
                    "request": context.request,
                    "seeds": context.seeds
                }
            )
        else:
            if not callable(engine):
                engine = pandora.load_objects(engine)

            items = pandora.invoke(
                func=engine,
                args=args,
                kwargs=kwargs,
                annotations={
                    air.Context: context,
                    Response: context.response,
                    Request: context.request,
                    Item: context.seeds
                },
                namespace={
                    "context": context,
                    "response": context.response,
                    "request": context.request,
                    "seeds": context.seeds
                }
            )

        if inspect.isgenerator(items):
            for item in items:
                yield item
        else:
            yield items or []

    def item_pipeline(self, context: air.Context):
        nodes: List[Pipeline] = pandora.iterable(self.config.pipeline)

        for node in nodes:
            engine = node.func
            args = node.args or []
            kwargs = node.kwargs or {}

            # todo: 暂时没有内置引擎, 后面需要加几个常用的
            if str(engine).lower() in []:
                pass
            else:
                if not callable(engine):
                    engine = pandora.load_objects(engine)

                pandora.invoke(
                    func=engine,
                    args=args,
                    kwargs=kwargs,
                    annotations={
                        air.Context: context,
                        Response: context.response,
                        Request: context.request,
                        Item: context.seeds,
                        Items: context.items
                    },
                    namespace={
                        "context": context,
                        "response": context.response,
                        "request": context.request,
                        "seeds": context.seeds,
                        "items": context.items
                    }
                )

            node.success and context.success()

    def install(self):
        super().install()

        for form, events in (self.config.events or {}).items():
            self.use(form, *events)