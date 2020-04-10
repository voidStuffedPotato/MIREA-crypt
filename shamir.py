#! /usr/bin/env python3
"""Реализует схему (n, k) разделения Шамира

   Примеры использования:
        keys = shamir_encrypt(246, 3, 5, mod=8707)
        (keys: [(8111, 7512), (4005, 2464), (8528, 3334), (2955, 7785), (2850, 5705)])


        keys = [(8111, 7512), (4005, 2464), (8528, 3334), (2955, 7785), (2850, 5705)]
        secret = shamir_decrypt(keys, mod=8707)
        (secret: 246)
"""

from functools import wraps
from common import is_prime
import random


class ShamirError(Exception):
    """Базовый класс всех исключений из модуля"""


class PrimeError(ShamirError):
    """Исключение для составных чисел"""


class CoalitionError(ShamirError):
    """Исключение для коалиций"""


def _filter_primes(func):
    """Проверяет простоту аргумента mod при вызовах func.

    Аргументы:
        func - оборачиваемая функция.

    Возвращает:
        Значение func(*pargs, **kwargs).

    Исключения:
        Выбрасывает исключение PrimeError, если именованный аргумент mod отсутствует
        или составное число.
    """

    @wraps(func)
    def filter_primes_inner(*pargs, **kwargs):
        if not is_prime(kwargs['mod']):
            return func(*pargs, **kwargs)
        str_ = "argument mod for %s must be prime" % func.__name__
        raise PrimeError(str_)

    return filter_primes_inner


def _polynomial(poly: list, x: int, mod: int) -> int:
    """Вычисляет многочлен в заданной точке.

    Аргументы:
        poly: коэффициенты многочлена от старшего к младшему.
        x: точка, в которой вычисляется значение.
        mod: порядок кольца вычетов, над которым вычисляется значение, простое число.

    Возвращает:
        Значение многочлена.
    """

    ret = 0
    for i, el in enumerate(poly[::-1]):
        ret += el * x ** i
    return ret % mod


def _get_lagrange_polynomial(keys: list, i: int, x: int, mod: int) -> list:
    """Вычисляет интерполяционный полином Лагранжа в заданной точке.

    Аргументы:
        keys: список точек, для которых считается полином.
        i: номер точки, в которой полином равен единице.
        mod: порядок кольца вычетов, над которым вычисляется значение, простое число.

    Возвращает:
        Значение многочлена.
    """
    ret = 1
    for pos, el in enumerate(keys):
        ret *= ((x - el) * pow((keys[i] - el) %
                               mod, -1, mod)) if pos != i else 1
    return ret % mod


@_filter_primes
def shamir_encrypt(secret: int, k: int, n: int, *, mod: int) -> list:
    """Зашифровывает секрет по (k, n) схеме Шамира.

    Параметры:
        secret: секрет.
        k: минимальное число участников коалиции для расшифрования.
        n: общее количество участников.
        mod: порядок кольца вычетов, используемый в схеме, простое число.

    Возвращает:
        Список из n ключей вида (int, int)

    Исключения:
        PrimeError, если n - составное.
        CoalitionError, если k > n или max(k, n) > mod или min(k, n) < 0
    """

    if min(n, k) < 0:
        msg = "Coalition size should be postive"
        raise CoalitionError(msg)
    if max(n, k) > mod:
        msg = "max(k, n) should be less or equal than modulo"
        raise CoalitionError(msg)
    if k > n:
        msg = "k should be less or equal than n"
        raise CoalitionError(msg)

    # младший коэффициент - секрет
    poly = [random.randint(0, mod - 1)
            for _ in range(k - 2)]
    poly.append(secret)

    # точки уникальные и случайные
    x = []
    curr = random.randint(0, mod - 1)
    while len(x) < n:
        while curr in x:
            curr = random.randint(0, mod - 1)
        x.append(curr)

    y = [(i, _polynomial(poly, i, mod)) for i in x]

    return y


@_filter_primes
def shamir_decrypt(keys: list, *, mod: int) -> int:
    """Расшифровывает секрет по (k, n) схеме Шамира.

    Расшифровывает секрет по (k, n) схеме Шамира, при этом не гарантируется правильность
    расшфрования, если количество членов коалиции k недостаточно или ключи участников некорректны.
    Также в таких случаях не выбрасывается исключение.

    Параметры:
        keys: список ключей вида (int, int).
        mod: порядок кольца вычетов, над которым вычисляются секрет, простое число.

    Возвращает:
        Зашифрованный cекрет.
    """
    x = [i[0] for i in keys]
    ret = sum([keys[i][1] * _get_lagrange_polynomial(x, i, 0, mod)
               for i in range(len(keys))])
    return ret % mod
