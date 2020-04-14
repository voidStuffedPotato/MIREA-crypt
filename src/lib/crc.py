#! /usr/bin/env python3
"""Реализует CRC-кодирование

  Пример использования:
 
    code = encode(0b1101010110001, 0b100010)
    (code: 437316)
    msg = decode(437316, 0b100010)
    (msg: 0b1101010110001)
    msg = decode(437317, 0b100010) # Ошибка в последнем бите
    (CryptError is raised)

"""

from .common import CryptError


def _modulo(a: int, b: int):
    """Возвращает остаток от деления полиномов в GF(2)

    Полиномы задаются натуральными числами, например x^4 + x^2 + 1 -> 0b10101 -> 21
    """
    cmp = 2 ** (len(bin(b)) - 3)
    iters = len(bin(a)) - len(bin(b))
    curr = a // (2 ** iters)
    for i in range(iters, -1, -1):
        curr ^= (b * (cmp & curr > 0))
        if i:
            curr = int(curr * 2 + ((a // (2 ** (i - 1))) % 2))

    return curr


def encode(target: int, poly: int):
    """Возвращает CRC-код a, от порождающего полинома b"""
    target = target * 2 ** (len(bin(poly)) - 2)
    target += _modulo(target, poly)
    return target + _modulo(target, poly)


def decode(target: int, poly: int):
    """Декодирует CRC-код, в случае ошибки выбрасывает CryptError"""
    errors = _modulo(target, poly)
    if not errors:
        return target // (2 ** (len(bin(poly)) - 2))
    raise CryptError("Encoding errors")
