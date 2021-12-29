import random
from string import ascii_letters, digits


def generate_password(words=ascii_letters, length=8, numbers=digits, characters=None,
                      first_upper=True):
    r = random.SystemRandom()
    elements = r.sample(words, length)

    if numbers:
        elements.insert(r.randint(1, len(elements)), r.choice(numbers))
    if characters:
        elements.insert(r.randint(1, len(elements)), r.choice(characters))
    if first_upper:
        elements[0] = elements[0].title()

    return ''.join(elements)