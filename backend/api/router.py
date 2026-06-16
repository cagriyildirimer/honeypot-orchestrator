from __future__ import annotations
from typing import Callable, Any, Coroutine

class APIRouter:
    def __init__(self) -> None:
        # Maps (method, path) -> handler function
        self.routes: dict[tuple[str, str], Callable[..., Coroutine[Any, Any, Any]]] = {}

    def get(self, path: str):
        def decorator(func: Callable[..., Coroutine[Any, Any, Any]]):
            self.routes[("GET", path)] = func
            return func
        return decorator

    def post(self, path: str):
        def decorator(func: Callable[..., Coroutine[Any, Any, Any]]):
            self.routes[("POST", path)] = func
            return func
        return decorator

    async def route(self, method: str, path: str, *args: Any, **kwargs: Any) -> Any:
        handler = self.routes.get((method, path))
        if handler:
            return await handler(*args, **kwargs)
        return None

# Global router instance to be imported by server and handlers
router = APIRouter()
