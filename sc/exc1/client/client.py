import socket
import sys
import time


HOSTNAME = 'target.myrelabs.com'
PORT = 7777

HOST = socket.gethostbyname(HOSTNAME)

TEST_ITERS = 10


def init_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
    except socket.error as err:
        print('socket err', err)
        sys.exit(1)
    return s


def test(p_index, password):
    result = 0
    for _ in range(TEST_ITERS):
        digest = p_index.to_bytes(1, 'little') + password
        start = time.time_ns()
        s.send(digest)
        res = s.recv(1)
        end = time.time_ns()
        result += (end - start) / 1_000_000 / TEST_ITERS
    return result, res == 1


def print_clients():
    s.send(index.to_bytes(4, 'little'), 4)
    clients = int.from_bytes(s.recv(4), 'little')
    print('Connected clients: ', clients)


def main():
    global s
    s = init_socket()

    index = 229747
    print_clients()

    s.send(bytes(range(9)))
    print(test(0, bytes(range(8))))


if __name__ == '__main__':
    main()
