"""Opaque immutable storage for the SDK's exported value objects.

Pure-Python tuple subclasses can always be forged with ``tuple.__new__``.
Keeping state in an identity-bound registry means base construction can create
only an unregistered shell; every observable operation fails closed unless the
module factory registered the instance.
"""

from __future__ import annotations

from collections.abc import Iterator
from threading import RLock
from typing import Any, SupportsIndex, TypeAlias, cast, overload
from weakref import ReferenceType, ref

_RegistryEntry: TypeAlias = tuple[
    ReferenceType["_OpaqueValueObject"],
    type["_OpaqueValueObject"],
    object,
]

_REGISTRY_LOCK = RLock()
_REGISTRY: dict[int, _RegistryEntry] = {}


def _register_opaque_state(
    instance: _OpaqueValueObject,
    state: object,
    *,
    exact_type: type[_OpaqueValueObject],
) -> None:
    if type(instance) is not exact_type:
        raise TypeError("only an exact public value-object type can be registered")
    identity = id(instance)

    def discard(dead_reference: ReferenceType[_OpaqueValueObject]) -> None:
        with _REGISTRY_LOCK:
            current = _REGISTRY.get(identity)
            if current is not None and current[0] is dead_reference:
                del _REGISTRY[identity]

    instance_reference = ref(instance, discard)
    with _REGISTRY_LOCK:
        current = _REGISTRY.get(identity)
        if current is not None and current[0]() is not None:
            raise RuntimeError("opaque value-object identity is already registered")
        _REGISTRY[identity] = (instance_reference, exact_type, state)


def _opaque_state(
    instance: _OpaqueValueObject,
    *,
    exact_type: type[_OpaqueValueObject] | None = None,
) -> object:
    with _REGISTRY_LOCK:
        current = _REGISTRY.get(id(instance))
        if (
            current is None
            or current[0]() is not instance
            or type(instance) is not current[1]
            or (exact_type is not None and current[1] is not exact_type)
        ):
            raise ValueError("value object was not created by its validated factory")
        return current[2]


class _OpaqueValueObject:
    """Sealed, tuple-compatible facade over identity-bound immutable state."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        if _OpaqueValueObject not in cls.__bases__:
            raise TypeError("public value-object classes are sealed")

    def _validated_sequence(self) -> tuple[object, ...]:
        raise NotImplementedError

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("value objects are immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("value objects are immutable")

    def __len__(self) -> int:
        _opaque_state(self)
        return len(self._validated_sequence())

    def __iter__(self) -> Iterator[object]:
        _opaque_state(self)
        return iter(self._validated_sequence())

    @overload
    def __getitem__(self, index: int) -> object: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[object, ...]: ...

    def __getitem__(self, index: int | slice) -> object | tuple[object, ...]:
        _opaque_state(self)
        return self._validated_sequence()[index]

    def __contains__(self, value: object) -> bool:
        _opaque_state(self)
        return value in self._validated_sequence()

    def count(self, value: object) -> int:
        _opaque_state(self)
        return self._validated_sequence().count(value)

    def index(self, value: object, start: int = 0, stop: int | None = None) -> int:
        _opaque_state(self)
        sequence = self._validated_sequence()
        return sequence.index(value, start) if stop is None else sequence.index(value, start, stop)

    def __repr__(self) -> str:
        _opaque_state(self)
        return repr(self._validated_sequence())

    def __eq__(self, other: object) -> bool:
        _opaque_state(self)
        if isinstance(other, _OpaqueValueObject):
            if type(other) is not type(self):
                return False
            _opaque_state(other)
            return self._validated_sequence() == other._validated_sequence()
        if type(other) is tuple:
            return self._validated_sequence() == cast(tuple[object, ...], other)
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        _opaque_state(self)
        if isinstance(other, _OpaqueValueObject) and type(other) is type(self):
            _opaque_state(other)
            return self._validated_sequence() < other._validated_sequence()
        if type(other) is tuple:
            return self._validated_sequence() < cast(tuple[object, ...], other)
        return NotImplemented

    def __hash__(self) -> int:
        _opaque_state(self)
        return hash(self._validated_sequence())

    def __copy__(self) -> _OpaqueValueObject:
        _opaque_state(self)
        self._validated_sequence()
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> _OpaqueValueObject:
        _opaque_state(self)
        self._validated_sequence()
        memo[id(self)] = self
        return self

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("value objects do not support pickle serialization")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("value objects do not support pickle serialization")
