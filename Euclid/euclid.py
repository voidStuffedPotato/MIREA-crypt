def euclid(a: int, b: int) -> int:
    if a == 0:
        return b
    else:
        return euclid(a % b, b)

print("Hello, world!")

