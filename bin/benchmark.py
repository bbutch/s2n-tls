#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

import subprocess
import sys
import os
import copy
import yaml

class Benchmark:
    def __init__(self, client_config, server_config):
        self.client_config = client_config
        self.server_config = server_config
        self.raw_nano_times = []
        self.sorted_nano_times = None
        self.nano_average = -1
        self.finalized = False

    def add_nano_time(self, time):
        if self.finalized:
            raise RuntimeError("Benchmark has already been finalized")

        self.raw_nano_times.append(time)

    def finalize(self):
        if self.finalized:
            return

        self.sorted_nano_times = copy.deepcopy(self.raw_nano_times)
        self.sorted_nano_times.sort()
        self.nano_average = sum(self.sorted_nano_times) // len(self.sorted_nano_times)  # Truncate it
        self.finalized = True

    def get_nano_average(self):
        if not self.finalized:
            raise RuntimeError("Benchmark has not been finalized")

        return self.nano_average

    def get_milli_average(self):
        return float(self.get_nano_average()) / float(1000000.0)

    def get_nano_p(self, p):
        if not self.finalized:
            raise RuntimeError("Benchmark has not been finalized")

        if (p < 0) or (p > 100):
            raise RuntimeError("Nonsense p value")

        if p == 100:
            i = len(self.sorted_nano_times) - 1
        else:
            i = int(len(self.sorted_nano_times) * (p/100))

        return self.sorted_nano_times[i]

    def get_milli_p(self, p):
        return float(self.get_nano_p(p)) / float(1000000.0)

    def get_wiki_row(self, p_list):
        if not self.finalized:
            raise RuntimeError("Benchmark has not been finalized")

        if self.client_config["tls_version"] == 33:
            tls_wiki_str = "(% style=\"color:grey\" %)**TLS 1.2**(% style=\"color:black\" %)"
        else:
            tls_wiki_str = "(% style=\"color:red\" %)**TLS 1.3**(% style=\"color:black\" %)"

        if self.client_config["kem_group"] != "NONE":
            handshake_params_str = self.client_config["kem_group"]
        elif self.client_config["kem"] != "NONE":
            handshake_params_str = "{} + {}".format(self.client_config["curve"], self.client_config["kem"])
        else:
            handshake_params_str = self.client_config["curve"]

        handshake_string = "(% style=\"color:{}\" %){}(% style=\"color:black\" %)".format(self.client_config["wiki_color"],
                                                                                          handshake_params_str)

        wiki_row_str = "|{} / {} / {}|{}".format(tls_wiki_str, handshake_string, self.client_config["cipher"],
                                                 self.get_milli_average())

        for p in p_list:
            wiki_row_str += "|{}".format(self.get_milli_p(p))

        return wiki_row_str

    def write_to_file(self):
        if self.client_config["tls_version"] == 33:
            tls_str = "tls12"
        else:
            tls_str = "tls13"

        if self.client_config["kem_group"] != "NONE":
            handshake_params_str = self.client_config["kem_group"]
        elif self.client_config["kem"] != "NONE":
            handshake_params_str = "{}_{}".format(self.client_config["curve"], self.client_config["kem"])
        else:
            handshake_params_str = self.client_config["curve"]

        filename = "{}_to_{}_{}_{}.txt".format(self.client_config["source"], self.server_config["destination"], tls_str,
                                               handshake_params_str)
        wiki_str = self.get_wiki_row([0, 50, 90, 95, 99, 99.9, 100])

        with open(filename, "w") as f:
            f.write("{}\n\n".format(wiki_str))
            f.write("protocol_version, cipher, curve, kem, kem_group, handshake_time_in_millis\n")
            for t in self.raw_nano_times:
                f.write("{},{},{},{},{},{}\n".format(self.client_config["tls_version"],
                                                     self.client_config["cipher"],
                                                     self.client_config["curve"],
                                                     self.client_config["kem"],
                                                     self.client_config["kem_group"],
                                                     str(float(t) / float(1000000.0))))

def run_benchmark(client_config, server_config):
    current_dir = os.path.dirname(os.path.realpath(__file__))
    s2nc_cmd = ["./s2nc", "--tls13", "-C", "--insecure", "--ciphers", client_config["security_policy"],
                server_config["host"], str(server_config["port"])]
    benchmark = Benchmark(client_config, server_config)
    successful = True

    print("{},{},{},{},{},{}".format(server_config["destination"], client_config["tls_version"],
                                     client_config["cipher"], client_config["curve"], client_config["kem"],
                                     client_config["kem_group"]))

    for r in range(client_config["rounds"]):
        s2nc = subprocess.run(s2nc_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=current_dir, encoding="utf-8")
        output = s2nc.stdout.splitlines()

        if (len(output) < 11) or\
                (str(client_config["tls_version"]) not in output[4]) or \
                (client_config["curve"] not in output[6]) or \
                (client_config["kem"] not in output[7]) or \
                (client_config["kem_group"] not in output[8]) or \
                (client_config["cipher"] not in output[9]):
            successful = False
            break

        nano_time = int(output[10].split(": ")[1])
        benchmark.add_nano_time(nano_time)
        if r == client_config["rounds"] - 1:
            print("Current benchmark...complete!           ", end='\n', flush=True)
        else:
            current_percent = int(float(r / client_config["rounds"]) * 100)
            print("Current benchmark progress...{}%".format(str(current_percent)), end='\r')

    if successful:
        benchmark.finalize()
        return benchmark
    else:
        print("FAILED :(")
        return None

def main(argv):
    with open(argv[0]) as f:
        clients = yaml.safe_load(f)

    with open(argv[1]) as f:
        servers = yaml.safe_load(f)

    total = len(clients) * len(servers)
    current = 1
    for server in servers:
        for client in clients:
            print("Benchmark: {}/{}".format(current, total))
            benchmark = run_benchmark(client, server)
            if benchmark is not None:
                benchmark.write_to_file()
            current += 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
