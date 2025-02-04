# UOV

This repository contains a Cortex-M4 implementation of the UOV NIST submission. 
It is compatible with the Round-2 version of the specification.
It based on the implementation described in the paper **Oil and Vinegar: Modern Parameters and Implementations** available [here](https://eprint.iacr.org/2023/059), but testvectors have changed in Round-2.

This repository is based on [pqm4](https://github.com/mupq/pqm4) and you will find the usual `test.py`, `testvectors.py`, and `benchmarks.py` scripts.  
Please follow the installation steps in pqm4. 
We target the [NUCLEO-L4R5ZI board](https://www.st.com/en/evaluation-tools/nucleo-l476rg.html), but tests can also be performed using qemu.


```
git clone --recurse-submodules https://github.com/pqov/pqov-m4/
cd pqov-m4
```

## Running tests and benchmarks
```
# run tests using qemu
./test.py -p mps2-an386
# run testvectors using qemu
./testvectors.py -p mps2-an386

# run tests on the board
./test.py -p nucleo-l4r5zi -u /dev/ttyACM0
# run testvectors on the board
./testvectors.py -p nucleo-l4r5zi -u /dev/ttyACM0
# run benchmarks on the board
./benchmarks.py -p nucleo-l4r5zi -u /dev/ttyACM0 -i 10
# print benchmarks
./convert_benchmarks.py md
```

## Benchmarks

| scheme | implementation | key generation [cycles] | sign [cycles] | verify [cycles] |
| ------ | -------------- | ----------------------- | ------------- | --------------- |
| ov-Ip (1 executions) | m4f | AVG: 138,756,740 <br /> MIN: 138,756,740 <br /> MAX: 138,756,740 | AVG: 2,509,469 <br /> MIN: 2,509,469 <br /> MAX: 2,509,469 | AVG: 998,985 <br /> MIN: 998,985 <br /> MAX: 998,985 |
| ov-Ip (1 executions) | ref | AVG: 350,354,485 <br /> MIN: 350,354,485 <br /> MAX: 350,354,485 | AVG: 6,678,636 <br /> MIN: 6,678,636 <br /> MAX: 6,678,636 | AVG: 1,303,273 <br /> MIN: 1,303,273 <br /> MAX: 1,303,273 |
| ov-Ip-pkc (1 executions) | m4f | AVG: 174,978,241 <br /> MIN: 174,978,241 <br /> MAX: 174,978,241 | AVG: 2,533,591 <br /> MIN: 2,533,591 <br /> MAX: 2,533,591 | AVG: 11,552,193 <br /> MIN: 11,552,193 <br /> MAX: 11,552,193 |
| ov-Ip-pkc (1 executions) | m4f-speed | AVG: 174,978,239 <br /> MIN: 174,978,239 <br /> MAX: 174,978,239 | AVG: 2,533,594 <br /> MIN: 2,533,594 <br /> MAX: 2,533,594 | AVG: 10,720,395 <br /> MIN: 10,720,395 <br /> MAX: 10,720,395 |
| ov-Ip-pkc (1 executions) | ref | AVG: 374,689,539 <br /> MIN: 374,689,539 <br /> MAX: 374,689,539 | AVG: 7,146,608 <br /> MIN: 7,146,608 <br /> MAX: 7,146,608 | AVG: 10,947,347 <br /> MIN: 10,947,347 <br /> MAX: 10,947,347 |
| ov-Ip-pkc-aes4 (1 executions) | m4f | AVG: 169,238,421 <br /> MIN: 169,238,421 <br /> MAX: 169,238,421 | AVG: 2,533,591 <br /> MIN: 2,533,591 <br /> MAX: 2,533,591 | AVG: 5,805,036 <br /> MIN: 5,805,036 <br /> MAX: 5,805,036 |
| ov-Ip-pkc-aes4 (1 executions) | m4f-speed | AVG: 169,238,415 <br /> MIN: 169,238,415 <br /> MAX: 169,238,415 | AVG: 2,533,594 <br /> MIN: 2,533,594 <br /> MAX: 2,533,594 | AVG: 5,420,706 <br /> MIN: 5,420,706 <br /> MAX: 5,420,706 |
| ov-Ip-pkc-aes4 (1 executions) | ref | AVG: 368,949,374 <br /> MIN: 368,949,374 <br /> MAX: 368,949,374 | AVG: 7,146,608 <br /> MIN: 7,146,608 <br /> MAX: 7,146,608 | AVG: 5,647,661 <br /> MIN: 5,647,661 <br /> MAX: 5,647,661 |
| ov-Ip-pkc-skc (1 executions) | m4f | AVG: 174,978,323 <br /> MIN: 174,978,323 <br /> MAX: 174,978,323 | AVG: 88,802,467 <br /> MIN: 88,802,467 <br /> MAX: 88,802,467 | AVG: 11,542,031 <br /> MIN: 11,542,031 <br /> MAX: 11,542,031 |
| ov-Ip-pkc-skc (1 executions) | m4f-speed | AVG: 174,978,325 <br /> MIN: 174,978,325 <br /> MAX: 174,978,325 | AVG: 91,261,472 <br /> MIN: 91,261,472 <br /> MAX: 91,261,472 | AVG: 11,434,554 <br /> MIN: 11,434,554 <br /> MAX: 11,434,554 |
| ov-Ip-pkc-skc (1 executions) | ref | AVG: 374,689,608 <br /> MIN: 374,689,608 <br /> MAX: 374,689,608 | AVG: 241,303,267 <br /> MIN: 241,303,267 <br /> MAX: 241,303,267 | AVG: 11,649,615 <br /> MIN: 11,649,615 <br /> MAX: 11,649,615 |
| ov-Ip-pkc-skc-aes4 (1 executions) | m4f | AVG: 169,238,495 <br /> MIN: 169,238,495 <br /> MAX: 169,238,495 | AVG: 83,062,341 <br /> MIN: 83,062,341 <br /> MAX: 83,062,341 | AVG: 5,787,334 <br /> MIN: 5,787,334 <br /> MAX: 5,787,334 |
| ov-Ip-pkc-skc-aes4 (1 executions) | m4f-speed | AVG: 169,238,495 <br /> MIN: 169,238,495 <br /> MAX: 169,238,495 | AVG: 83,062,335 <br /> MIN: 83,062,335 <br /> MAX: 83,062,335 | AVG: 5,740,053 <br /> MIN: 5,740,053 <br /> MAX: 5,740,053 |
| ov-Ip-pkc-skc-aes4 (1 executions) | ref | AVG: 368,949,458 <br /> MIN: 368,949,458 <br /> MAX: 368,949,458 | AVG: 235,563,153 <br /> MIN: 235,563,153 <br /> MAX: 235,563,153 | AVG: 5,909,504 <br /> MIN: 5,909,504 <br /> MAX: 5,909,504 |
| ov-Is (1 executions) | m4f-flash | AVG: 398,085,875 <br /> MIN: 398,085,875 <br /> MAX: 398,085,875 | AVG: 2,299,219 <br /> MIN: 2,299,219 <br /> MAX: 2,299,219 | AVG: 657,017 <br /> MIN: 657,017 <br /> MAX: 657,017 |
| ov-Is (1 executions) | ref-flash | AVG: 634,922,297 <br /> MIN: 634,922,297 <br /> MAX: 634,922,297 | AVG: 4,772,902 <br /> MIN: 4,772,902 <br /> MAX: 4,772,902 | AVG: 1,044,707 <br /> MIN: 1,044,707 <br /> MAX: 1,044,707 |
| ov-Is-pkc (1 executions) | m4f-flash | AVG: 314,104,049 <br /> MIN: 314,104,049 <br /> MAX: 314,104,049 | AVG: 2,299,226 <br /> MIN: 2,299,226 <br /> MAX: 2,299,226 | AVG: 16,042,825 <br /> MIN: 16,042,825 <br /> MAX: 16,042,825 |
| ov-Is-pkc (1 executions) | m4f-flash-speed | AVG: 314,104,043 <br /> MIN: 314,104,043 <br /> MAX: 314,104,043 | AVG: 2,299,219 <br /> MIN: 2,299,219 <br /> MAX: 2,299,219 | AVG: 15,459,859 <br /> MIN: 15,459,859 <br /> MAX: 15,459,859 |
| ov-Is-pkc (1 executions) | ref-flash | AVG: 540,910,911 <br /> MIN: 540,910,911 <br /> MAX: 540,910,911 | AVG: 4,772,863 <br /> MIN: 4,772,863 <br /> MAX: 4,772,863 | AVG: 16,409,381 <br /> MIN: 16,409,381 <br /> MAX: 16,409,381 |
| ov-Is-pkc-aes4 (1 executions) | m4f-flash | AVG: 305,658,328 <br /> MIN: 305,658,328 <br /> MAX: 305,658,328 | AVG: 2,299,222 <br /> MIN: 2,299,222 <br /> MAX: 2,299,222 | AVG: 7,583,263 <br /> MIN: 7,583,263 <br /> MAX: 7,583,263 |
| ov-Is-pkc-aes4 (1 executions) | m4f-flash-speed | AVG: 305,658,331 <br /> MIN: 305,658,331 <br /> MAX: 305,658,331 | AVG: 2,299,224 <br /> MIN: 2,299,224 <br /> MAX: 2,299,224 | AVG: 7,418,434 <br /> MIN: 7,418,434 <br /> MAX: 7,418,434 |
| ov-Is-pkc-aes4 (1 executions) | ref-flash | AVG: 532,465,090 <br /> MIN: 532,465,090 <br /> MAX: 532,465,090 | AVG: 4,772,913 <br /> MIN: 4,772,913 <br /> MAX: 4,772,913 | AVG: 8,009,254 <br /> MIN: 8,009,254 <br /> MAX: 8,009,254 |
| ov-Is-pkc-skc (1 executions) | m4f-flash | AVG: 314,483,005 <br /> MIN: 314,483,005 <br /> MAX: 314,483,005 | AVG: 113,373,518 <br /> MIN: 113,373,518 <br /> MAX: 113,373,518 | AVG: 16,059,174 <br /> MIN: 16,059,174 <br /> MAX: 16,059,174 |
| ov-Is-pkc-skc (1 executions) | m4f-flash-speed | AVG: 314,482,997 <br /> MIN: 314,482,997 <br /> MAX: 314,482,997 | AVG: 113,373,516 <br /> MIN: 113,373,516 <br /> MAX: 113,373,516 | AVG: 14,907,147 <br /> MIN: 14,907,147 <br /> MAX: 14,907,147 |
| ov-Is-pkc-skc (1 executions) | ref-flash | AVG: 541,396,424 <br /> MIN: 541,396,424 <br /> MAX: 541,396,424 | AVG: 219,679,005 <br /> MIN: 219,679,005 <br /> MAX: 219,679,005 | AVG: 16,437,913 <br /> MIN: 16,437,913 <br /> MAX: 16,437,913 |
| ov-Is-pkc-skc-aes4 (1 executions) | m4f-flash | AVG: 306,037,286 <br /> MIN: 306,037,286 <br /> MAX: 306,037,286 | AVG: 104,927,680 <br /> MIN: 104,927,680 <br /> MAX: 104,927,680 | AVG: 7,571,510 <br /> MIN: 7,571,510 <br /> MAX: 7,571,510 |
| ov-Is-pkc-skc-aes4 (1 executions) | m4f-flash-speed | AVG: 306,037,280 <br /> MIN: 306,037,280 <br /> MAX: 306,037,280 | AVG: 104,927,684 <br /> MIN: 104,927,684 <br /> MAX: 104,927,684 | AVG: 7,157,320 <br /> MIN: 7,157,320 <br /> MAX: 7,157,320 |
| ov-Is-pkc-skc-aes4 (1 executions) | ref-flash | AVG: 532,950,654 <br /> MIN: 532,950,654 <br /> MAX: 532,950,654 | AVG: 211,233,225 <br /> MIN: 211,233,225 <br /> MAX: 211,233,225 | AVG: 8,080,027 <br /> MIN: 8,080,027 <br /> MAX: 8,080,027 |
