from src import *
import csv
import random


def test_prg():
    with open('./inputs/prg.csv', 'r') as inpf:
        with open('./output/prg.txt') as outf:
            reader = csv.reader(inpf)
            tcs = [list(map(int, row))
                   for i, row in enumerate(reader) if i > 0]
            for tc in tcs:
                prg = PRG(*tc[:4])
                res = prg.generate(tc[4])
                output = outf.readline().strip()
                assert res == output


def test_prf():
    with open('./inputs/prf.csv', 'r') as inpf:
        with open('./output/prf.txt') as outf:
            reader = csv.reader(inpf)
            tcs = [list(map(int, row))
                   for i, row in enumerate(reader) if i > 0]
            for tc in tcs:
                prf = PRF(*tc[:4])
                res = prf.evaluate(tc[4])
                output = int(outf.readline().strip())
                assert res == output


def test_eav():
    with open('./inputs/eav.csv', 'r') as inpf:
        with open('./output/eav.txt') as outf:
            reader = csv.reader(inpf)
            tcs = [list(map(int, row[:5])) + [row[5]]
                   for i, row in enumerate(reader) if i > 0]
            for tc in tcs:
                eav = Eavesdrop(*tc[:5])
                res = eav.enc(tc[5])
                output = outf.readline().strip()
                assert res == output
                assert tc[5] == eav.dec(res)


def test_cpa():
    with open('./inputs/cpa.csv', 'r') as inpf:
        with open('./output/cpa.txt') as outf:
            reader = csv.reader(inpf)
            tcs = [list(map(int, row[:4])) + [row[4], int(row[5])]
                   for i, row in enumerate(reader) if i > 0]
            for tc in tcs:
                cpa = CPA(*tc[:4])
                res = cpa.enc(*tc[4:])
                output = outf.readline().strip()
                assert res == output
                assert tc[4] == cpa.dec(res)


def test_mac():
    with open('./inputs/mac.csv', 'r') as inpf:
        with open('./output/mac.txt') as outf:
            reader = csv.reader(inpf)
            tcs = [list(map(int, row[:4])) + [row[4], int(row[5])]
                   for i, row in enumerate(reader) if i > 0]
            for tc in tcs:
                mac = MAC(*tc[:4])
                tag = mac.mac(*tc[4:])
                output = outf.readline().strip()
                assert tag == output
                assert mac.vrfy(tc[4], tag)


def test_cbc_mac():
    with open('./inputs/cbc_mac.csv', 'r') as inpf:
        with open('./output/cbc_mac.txt') as outf:
            reader = csv.reader(inpf)
            for i, row in enumerate(reader):
                if i == 0:
                    continue
                n, g, p, k1, k2 = list(map(int, row[:-1]))
                m = row[-1]
                l = len(m)//n
                mac = CBC_MAC(n, g, p, l, (k1, k2))
                tag = mac.mac(m)
                output = int(outf.readline().strip())
                assert tag == output
                assert mac.vrfy(m, tag)

def test_cca():
    with open('./inputs/cca.csv', 'r') as inpf:
        with open('./output/cca.txt') as outf:
            reader = csv.reader(inpf)
            for i, row in enumerate(reader):
                if i == 0:
                    continue
                n, p, g, kcpa, k1, k2 = list(map(int, row[:-2]))
                message = row[-2]
                r = int(row[-1])
                cca = CCA(n, p, g, kcpa, (k1,k2))
                cipher = cca.enc(message, r)
                output = outf.readline().strip()
                assert cipher == output
                assert cca.dec(cipher)

