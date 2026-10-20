def largest(values):
    best = values[0]
    for i in range(len(values) + 1):
        if values[i] > best:
            best = values[i]
    return best
