#! /usr/bin/env python3
"""Содержит класс цифровой подписи на основе протокола RSA.

  Пример использования:

  msg = b'My secret message'
  rsa = RsaSignature()
  rsa.update(msg)
  sign = rsa.signature()
  key = rsa.get_pubkey()
  orig = rsa.compare_signature(sign, key)
  (True)
"""

import hashlib
import common


class RsaSignature(object):
    """Класс электронной подписи на основе алгоритма RSA"""
    def __init__(self):
        self._msg = b''
        self._generate_keys()
        self._hash = hashlib.md5()

    def _generate_keys(self) -> None:
        """Генерирует закрытый и открытый ключ."""

        p = common.random_prime(2 ** 16)
        # p != q
        q = 0
        while (not q) or (p == q):
            q = common.random_prime(2 ** 16)

        self._n = p * q
        phi = (p - 1) * (q - 1)
        self._e = common.random_prime(phi)
        self._d = pow(self._e, -1, phi)

    def update(self, msg: bytes) -> None:
        """Заменяет сообщение и его подпись.

        Аргументы:
            msg: строка байт, заменяющая сообщение.
        """
        self._msg = msg
        self._hash.update(msg)
        self._sign()

    def _sign(self) -> None:
        """Обновляет состояние подписи после изменения сообщения."""
        digest = int(self._hash.hexdigest(), 16) % self._n
        self._signature = hex(pow(digest, self._d, self._n)).encode()

    def get_pubkey(self) -> (int, int):
        """Возвращает открытый ключ вида (int, int)"""
        return (self._e, self._n)

    def signature(self) -> (bytes, bytes):
        """Возвращает цифровую подпись

        Возвращает:
            подпись в виде tuple(bytes, bytes),
            Первое поле - зашифрованый хэш md5 в hex-формате, второе - оригинальное сообщение.
        """
        return (self._signature, self._msg)

    @staticmethod
    def compare_signature(signature: (bytes, bytes), pubkey: (int, int)) -> bool:
        """Проверяет оригинальность цифровой подписи

        Аргументы:
            signature: цифровая подпись вида (bytes, bytes),
                возвращенная методом RsaSignature.signature().
            pubkey: открытый ключ автора цифровой подписи вида (int, int),
                возвращенный методом RsaSignature.get_pubkey().

        Возвращает:
            True, если подпись оригинальна, иначе False.
        """
        e, n = pubkey
        sign, msg = signature

        # расшифрованный хэш сообщения
        sign_digest = str(pow(int(sign, 16), e, n)).encode()

        hash_ = hashlib.md5()
        hash_.update(msg)
        # хэш сообщения
        digest = str(int(hash_.hexdigest(), 16) % n).encode()

        return digest == sign_digest


def main():
    """Тестирование модуля"""
    msg = b"Secret message"

    rsa = RsaSignature()
    rsa.update(msg)

    sign = rsa.signature()
    print("Подпись: ", sign)

    key = rsa.get_pubkey()
    print(f"Публичный ключ: (m: {key[1]}, e: {key[0]})")

    orig = rsa.compare_signature(sign, key)

    print('Подпись проверена', end='\t')
    print('[OK]' if orig else 'Ошибка')

if __name__ == '__main__':
    main()
