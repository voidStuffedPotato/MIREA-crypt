#! /usr/bin/env python3
"""Содержит класс цифровой подписи и протокола аутентификации на основе алгоритма RSA.

  Примеры использования:

  msg = b'My secret message'
  rsa_sig = RsaSignature()
  rsa_sig.update(msg)

  sign = rsa_sig.signature()
  key = rsa_sig.get_pubkey()

  orig = rsa_sig.compare_signature(sign, key)
  (True)

  rsa_1 = RsaPlain()
  rsa_2 = RsaPlain()

  rsa_client = RsaPlain()

  pubkey = rsa_1.get_pubkey()

  challenge_2 = rsa_client.generate_message(pubkey)

  response_2 = rsa_2.encrypt(challenge_2)

  original_2 = rsa_client.decrypt(response_2, pubkey) == challenge_2
  (Flase)
"""

import hashlib
import common


class RsaPlain(object):
    """Класс протокола аутентификации на основе алгоритма RSA

    Каждый экземпляр представляет собеседника в протоколе.
    Субъект аутентификации заранее предъявляет свой открытый ключ,
    используя метод get_pubkey(). Затем его идентичность проверяется
    другим экземпляром с помощью метода prove_identity().
    Пример использования в описании модуля.
    """

    def __init__(self):
        self._generate_keys()

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

    def get_pubkey(self) -> (int, int):
        """Возвращает открытый ключ вида (int, int)"""
        return (self._e, self._n)

    def encrypt(self, message: int):
        """Возвращает message, зашифрованное закрытым ключом

        Для проверки идентичности необходимо использовать
        RsaPlain.decrypt().
        """
        return pow(message, self._d, self._n)


    @staticmethod
    def decrypt(cipher: int, pubkey: (int, int)) -> bool:
        """Проверяет идентичность собеседника.

        Параметры:
            cipher: шифротекст, зашифрованный закрытым ключом.
            pubkey: открытый ключ для проверки идентичности.

        Возвращает:
            Расшифрованное сообщение.
        """
        return pow(cipher, *pubkey)

    @staticmethod
    def generate_message(pubkey: (int, int)) -> int:
        """Генерирует сообщение для аутентификации по открытому ключу pubkey"""
        return common.random_prime(pubkey[1])


class RsaSignature(RsaPlain):
    """Класс электронной подписи на основе алгоритма RSA"""

    def __init__(self):
        super().__init__()
        self._msg = b''
        self._hash = hashlib.md5()

    def update(self, msg: bytes) -> None:
        """Заменяет сообщение и его подпись.

        Аргументы:
            msg: строка байт, заменяющая сообщение.
        """
        if self._msg != msg:
            self._msg = msg
            self._hash.update(msg)
            self._sign()

    def _sign(self) -> None:
        """Обновляет состояние подписи после изменения сообщения."""
        digest = int(self._hash.hexdigest(), 16) % self._n
        self._signature = hex(pow(digest, self._d, self._n)).encode()

    def signature(self) -> (bytes, bytes):
        """Возвращает цифровую подпись

        Возвращает:
            подпись в виде tuple(bytes, bytes),
            Первое поле - зашифрованый хэш md5 в hex-формате,
            второе - оригинальное сообщение.
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

    rsa_sig = RsaSignature()
    rsa_sig.update(msg)

    sign = rsa_sig.signature()
    print("Подпись: ", sign)

    key = rsa_sig.get_pubkey()
    print(f"Публичный ключ: (m: {key[1]}, e: {key[0]})")

    orig = rsa_sig.compare_signature(sign, key)

    print('Подпись проверена', end='\t')
    print('[OK]' if orig else 'Ошибка')

    rsa_1 = RsaPlain()
    rsa_2 = RsaPlain()

    rsa_client = RsaPlain()

    pubkey = rsa_1.get_pubkey()

    challenge_1 = rsa_client.generate_message(pubkey)
    challenge_2 = rsa_client.generate_message(pubkey)

    response_1 = rsa_1.encrypt(challenge_1)
    response_2 = rsa_2.encrypt(challenge_2)

    original_1 = rsa_client.decrypt(response_1, pubkey) == challenge_1
    original_2 = rsa_client.decrypt(response_2, pubkey) == challenge_2

    if original_1:
        print("Аутентификация пройдена успешно")
    else:
        print("Аутентификация провалена")

    if original_2:
        print("Аутентификация пройдена успешно")
    else:
        print("Аутентификация провалена")


if __name__ == '__main__':
    main()
