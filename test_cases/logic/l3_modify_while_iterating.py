def remove_negatives(numbers):
    for number in numbers:
        if number < 0:
            numbers.remove(number)
    return numbers
