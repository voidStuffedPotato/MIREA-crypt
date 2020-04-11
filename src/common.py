"""Содержит общие функции для криптографических алгоритмов"""

import random


class CryptError(Exception):
    """Базовое исключение модуля"""


def is_prime(n: int) -> bool:
    """Проверяет n на простоту.

    Аргументы:
        n: проверяемое число.

    Возвращает:
        True, если число простое, иначе False.
    """
    i = 2
    flag = True

    while i ** 2 < n:
        if n % i == 0:
            flag = False
            break
        i += 1

    return flag


def get_prime(a: int, b: int):
    """Возвращает наименьшее простое число из полуинтервала [a, b)

    Аргументы:
        a: нижняя граница отрезка
        b: верхняя граница отрезка

    Возвращает:
        Наименьшее простое число из [a, b), либо если таких нет - None
    """
    curr = a

    while not is_prime(curr):
        curr += 1
        if curr >= b:
            return None

    return curr


def random_prime(limit: int = 10000):
    """Возвращает случайное простое число меньшее limit

    Криптостойкость не гарантируется.

    Аргументы:
        limit: верхняя граница генерируемых чисел, 10000 по умолчанию.

    Возвращает:
        Простое число, меньшее limit.

    Исключения:
        CryptError, если limit < 2.
    """

    if limit < 2:
        raise CryptError("limit must be greater or equal to 2")

    rand = random.randint(1, limit)
    ret_val = get_prime(rand, limit)

    while not ret_val:
        rand = random.randint(1, limit)
        ret_val = get_prime(rand, limit)

    return ret_val
