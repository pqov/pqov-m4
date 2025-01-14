import os
import numpy as np

schemes = ["ov-Ip", "ov-Ip-pkc", "ov-Ip-pkc-skc",
           "ov-Is", "ov-Is-pkc", "ov-Is-pkc-skc",
           "ov-Ip-pkc-aes4", "ov-Ip-pkc-skc-aes4",
           "ov-Is-pkc-aes4", "ov-Is-pkc-skc-aes4"
           ]



# parse
for test in ["speed"]:
    benchmarks = dict()
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print(f"% {test.upper()}")
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    for scheme in schemes:
        schemeDir = os.path.join("benchmarks", test, "crypto_sign", scheme)

        if not os.path.exists(schemeDir):
            continue

        for implementation in os.listdir(schemeDir):
            schemeImpl = f"{scheme}-{implementation}"

            bench = {
                "kg" : [],
                "sig" : [],
                "ver" : []
            }

            implDir = os.path.join(schemeDir, implementation)
            for benchmark in os.listdir(implDir):
                with open(os.path.join(implDir, benchmark)) as f:
                    fileContents = f.read()

                parts = fileContents.split("\n")

                if test == "speed":
                    try:
                        keygen    = int(parts[parts.index("keypair cycles:")+1])
                    except:
                        keygen = None

                    try:
                        keygenflashing    = int(parts[parts.index("flashing cycles:")+1])
                    except:
                        keygenflashing = None

                    try:
                        keygenwoflashing    = int(parts[parts.index("keypair (w/o writing to flash) cycles:")+1])
                    except:
                        keygenwoflashing = None

                    encsign    = int(parts[parts.index("sign cycles:")+1])
                    decverify    = int(parts[parts.index("verify cycles:")+1])
                elif test == "stack":
                    try:
                        keygen    = int(parts[parts.index("keypair stack usage:")+1])
                    except:
                        keygen = None
                    encsign     = int(parts[parts.index("sign stack usage:")+1])
                    decverify   = int(parts[parts.index("verify stack usage:")+1])

                #print(keygen, encsign, decverify)
                if keygen:
                    bench["kg"] += [keygen]
                if keygenflashing:
                    if "kg_flashing" not in bench:
                        bench["kg_flashing"] = []
                    bench["kg_flashing"] += [keygenflashing]
                if keygenwoflashing:
                    if "kg_woflashing" not in bench:
                        bench["kg_woflashing"] = []
                    bench["kg_woflashing"] += [keygenwoflashing]

                bench["sig"] += [encsign]
                bench["ver"] += [decverify]

            benchmarks[schemeImpl] = bench



    def formatValue(value):
        if test == "speed":
            value = f"{round(value/1000):,}k"
        elif test == "stack":
            value = f"{round(value):,}"
        value = value.replace(",", "\\,")
        return value


    def defineVar(key, value):
        value = formatValue(value)
        print(f"\\DefineVar{{{key}}}{{{value}}}")

    # average and print
    for schemeImpl in benchmarks.keys():
        bench = benchmarks[schemeImpl]
        numKg = len(bench["kg"])
        numSig = len(bench["sig"])
        numVer = len(bench["ver"])
        print(f"% {schemeImpl} KeyGen: {numKg} iterations; Sign: {numSig} iterations; Verify: {numVer} iterations; ")
        benchKey = f"{schemeImpl}_{test}"

        key = f"{benchKey}_keygen"
        value = np.mean(bench["kg"])
        defineVar(key, value)

        key = f"{benchKey}_sig"
        value = np.mean(bench["sig"])
        defineVar(key, value)

        key = f"{benchKey}_ver"
        value = np.mean(bench["ver"])
        defineVar(key, value)

        if "kg_flashing" in bench:
            key = f"{benchKey}_keygen_flashing"
            value = np.mean(bench["kg_flashing"])
            defineVar(key, value)

        if "kg_woflashing" in bench:
            key = f"{benchKey}_keygen_woflashing"
            value = np.mean(bench["kg_woflashing"])
            defineVar(key, value)