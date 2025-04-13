import threading
from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls

def generate_message(client_id):
    return f"Hello from Client {client_id}".encode()

def setup_clients(num_clients):
    clients = []
    for i in range(num_clients):
        sk = bls.KeyGen(i.to_bytes(4, 'big'))
        pk = bls.SkToPk(sk)
        msg = generate_message(i)
        clients.append({'id': i, 'sk': sk, 'pk': pk, 'msg': msg})
    return clients

def sign_and_verify(client, results):
    sig = bls.Sign(client['sk'], client['msg'])
    valid = bls.Verify(client['pk'], client['msg'], sig)
    results[client['id']] = valid

def run_simulation(num_clients):
    clients = setup_clients(num_clients)
    results = {}
    threads = []
    for client in clients:
        t = threading.Thread(target=sign_and_verify, args=(client, results))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    for cid in sorted(results):
        print(f"Client {cid}: Signature verification {'succeeded' if results[cid] else 'failed'}")

if __name__ == "__main__":
    client_count = int(input("Enter number of clients to simulate: "))
    run_simulation(client_count)
