# UOV

This repository contains a Cortex-M4 implementation of the UOV NIST submission. 
It is compatible with the Round-3 version of the specification.
It based on the implementation described in the paper **Oil and Vinegar: Modern Parameters and Implementations** available [here](https://eprint.iacr.org/2023/059), but testvectors have changed since.

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
./benchmarks.py -p nucleo-l4r5zi -u /dev/ttyACM0 -i 1000
# print benchmarks
./convert_benchmarks.py md
```

## Benchmarks

| scheme | implementation | key generation [cycles] | sign [cycles] | verify [cycles] |
| ------ | -------------- | ----------------------- | ------------- | --------------- |
| ov-Ip (1000 executions) | m4f | AVG: 178,017,933 <br /> MIN: 178,017,933 <br /> MAX: 178,017,933 | AVG: 3,049,645 <br /> MIN: 3,031,832 <br /> MAX: 5,999,579 | AVG: 1,433,039 <br /> MIN: 1,381,734 <br /> MAX: 1,438,779 |
| ov-Ip (1000 executions) | ref | AVG: 404,281,293 <br /> MIN: 404,281,293 <br /> MAX: 404,281,293 | AVG: 7,030,355 <br /> MIN: 7,016,544 <br /> MAX: 13,915,088 | AVG: 1,882,101 <br /> MIN: 1,882,095 <br /> MAX: 1,882,136 |
| ov-Ip-pkc (1000 executions) | m4f | AVG: 229,685,467 <br /> MIN: 229,685,467 <br /> MAX: 229,685,467 | AVG: 3,077,616 <br /> MIN: 3,068,605 <br /> MAX: 6,069,891 | AVG: 13,852,849 <br /> MIN: 13,799,377 <br /> MAX: 13,858,455 |
| ov-Ip-pkc (1000 executions) | m4f-speed | AVG: 229,685,411 <br /> MIN: 229,685,411 <br /> MAX: 229,685,411 | AVG: 3,071,611 <br /> MIN: 3,068,603 <br /> MAX: 6,069,885 | AVG: 12,775,625 <br /> MIN: 12,721,636 <br /> MAX: 12,780,623 |
| ov-Ip-pkc (1000 executions) | ref | AVG: 419,819,976 <br /> MIN: 419,819,976 <br /> MAX: 419,819,976 | AVG: 7,357,291 <br /> MIN: 7,328,467 <br /> MAX: 14,530,222 | AVG: 13,098,981 <br /> MIN: 13,098,957 <br /> MAX: 13,098,994 |
| ov-Ip-pkc-aes4 (1000 executions) | m4f | AVG: 222,968,889 <br /> MIN: 222,968,889 <br /> MAX: 222,968,889 | AVG: 3,083,614 <br /> MIN: 3,068,601 <br /> MAX: 6,069,922 | AVG: 7,130,813 <br /> MIN: 7,083,507 <br /> MAX: 7,136,180 |
| ov-Ip-pkc-aes4 (1000 executions) | m4f-speed | AVG: 222,968,943 <br /> MIN: 222,968,943 <br /> MAX: 222,968,943 | AVG: 3,077,616 <br /> MIN: 3,068,606 <br /> MAX: 6,069,932 | AVG: 6,576,061 <br /> MIN: 6,519,714 <br /> MAX: 6,581,355 |
| ov-Ip-pkc-aes4 (1000 executions) | ref | AVG: 413,105,277 <br /> MIN: 413,105,277 <br /> MAX: 413,105,277 | AVG: 7,371,683 <br /> MIN: 7,328,455 <br /> MAX: 14,530,203 | AVG: 6,899,700 <br /> MIN: 6,899,686 <br /> MAX: 6,899,725 |
| ov-Ip-pkc-skc (1000 executions) | m4f | AVG: 229,685,341 <br /> MIN: 229,685,341 <br /> MAX: 229,685,341 | AVG: 20,284,882 <br /> MIN: 20,269,801 <br /> MAX: 27,804,439 | AVG: 13,852,552 <br /> MIN: 13,796,635 <br /> MAX: 13,858,451 |
| ov-Ip-pkc-skc (1000 executions) | m4f-speed | AVG: 229,685,334 <br /> MIN: 229,685,334 <br /> MAX: 229,685,334 | AVG: 20,299,824 <br /> MIN: 20,269,676 <br /> MAX: 27,804,176 | AVG: 13,686,538 <br /> MIN: 13,633,281 <br /> MAX: 13,691,799 |
| ov-Ip-pkc-skc (1000 executions) | ref | AVG: 419,820,014 <br /> MIN: 419,820,014 <br /> MAX: 419,820,014 | AVG: 29,863,857 <br /> MIN: 29,795,819 <br /> MAX: 46,797,080 | AVG: 14,021,142 <br /> MIN: 14,021,108 <br /> MAX: 14,021,154 |
| ov-Ip-pkc-skc-aes4 (1000 executions) | m4f | AVG: 222,968,792 <br /> MIN: 222,968,792 <br /> MAX: 222,968,792 | AVG: 13,562,637 <br /> MIN: 13,555,066 <br /> MAX: 21,089,491 | AVG: 7,129,723 <br /> MIN: 7,073,575 <br /> MAX: 7,136,177 |
| ov-Ip-pkc-skc-aes4 (1000 executions) | m4f-speed | AVG: 222,968,821 <br /> MIN: 222,968,821 <br /> MAX: 222,968,821 | AVG: 13,570,348 <br /> MIN: 13,555,248 <br /> MAX: 21,089,861 | AVG: 6,971,768 <br /> MIN: 6,928,068 <br /> MAX: 6,977,349 |
| ov-Ip-pkc-skc-aes4 (1000 executions) | ref | AVG: 413,105,504 <br /> MIN: 413,105,504 <br /> MAX: 413,105,504 | AVG: 23,166,412 <br /> MIN: 23,081,388 <br /> MAX: 40,082,706 | AVG: 7,306,674 <br /> MIN: 7,306,658 <br /> MAX: 7,306,701 |
| ov-Is (1000 executions) | m4f-flash | AVG: 398,061,881 <br /> MIN: 398,061,881 <br /> MAX: 398,061,881 | AVG: 2,408,849 <br /> MIN: 2,293,873 <br /> MAX: 6,715,860 | AVG: 616,034 <br /> MIN: 536,294 <br /> MAX: 674,758 |
| ov-Is (1000 executions) | ref-flash | AVG: 627,775,561 <br /> MIN: 627,775,561 <br /> MAX: 627,775,561 | AVG: 4,717,736 <br /> MIN: 4,399,562 <br /> MAX: 17,298,186 | AVG: 930,890 <br /> MIN: 793,543 <br /> MAX: 1,026,682 |
| ov-Is-pkc (1000 executions) | m4f-flash | AVG: 314,105,243 <br /> MIN: 314,105,243 <br /> MAX: 314,105,243 | AVG: 2,444,227 <br /> MIN: 2,293,876 <br /> MAX: 6,715,868 | AVG: 16,043,364 <br /> MIN: 15,978,484 <br /> MAX: 16,075,451 |
| ov-Is-pkc (1000 executions) | m4f-flash-speed | AVG: 314,105,249 <br /> MIN: 314,105,249 <br /> MAX: 314,105,249 | AVG: 2,419,900 <br /> MIN: 2,293,869 <br /> MAX: 6,715,808 | AVG: 15,162,478 <br /> MIN: 13,722,869 <br /> MAX: 16,164,642 |
| ov-Is-pkc (1000 executions) | ref-flash | AVG: 533,468,259 <br /> MIN: 533,468,259 <br /> MAX: 533,468,259 | AVG: 4,713,437 <br /> MIN: 4,399,562 <br /> MAX: 12,998,627 | AVG: 16,470,545 <br /> MIN: 16,320,870 <br /> MAX: 16,571,383 |
| ov-Is-pkc-aes4 (1000 executions) | m4f-flash | AVG: 305,659,504 <br /> MIN: 305,659,504 <br /> MAX: 305,659,504 | AVG: 2,466,338 <br /> MIN: 2,293,877 <br /> MAX: 8,926,796 | AVG: 7,592,743 <br /> MIN: 7,542,958 <br /> MAX: 7,624,755 |
| ov-Is-pkc-aes4 (1000 executions) | m4f-flash-speed | AVG: 305,659,509 <br /> MIN: 305,659,509 <br /> MAX: 305,659,509 | AVG: 2,439,805 <br /> MIN: 2,293,874 <br /> MAX: 6,715,870 | AVG: 7,244,475 <br /> MIN: 6,421,172 <br /> MAX: 7,727,102 |
| ov-Is-pkc-aes4 (1000 executions) | ref-flash | AVG: 525,022,501 <br /> MIN: 525,022,501 <br /> MAX: 525,022,501 | AVG: 4,704,846 <br /> MIN: 4,399,570 <br /> MAX: 12,998,641 | AVG: 8,024,321 <br /> MIN: 7,892,035 <br /> MAX: 8,115,243 |
| ov-Is-pkc-skc (1000 executions) | m4f-flash | AVG: 314,483,932 <br /> MIN: 314,483,932 <br /> MAX: 314,483,932 | AVG: 21,435,229 <br /> MIN: 21,069,764 <br /> MAX: 36,959,008 | AVG: 16,043,343 <br /> MIN: 16,001,564 <br /> MAX: 16,077,074 |
| ov-Is-pkc-skc (1000 executions) | m4f-flash-speed | AVG: 314,483,936 <br /> MIN: 314,483,936 <br /> MAX: 314,483,936 | AVG: 21,461,721 <br /> MIN: 21,069,773 <br /> MAX: 36,958,994 | AVG: 15,163,705 <br /> MIN: 13,631,128 <br /> MAX: 16,178,420 |
| ov-Is-pkc-skc (1000 executions) | ref-flash | AVG: 533,953,678 <br /> MIN: 533,953,678 <br /> MAX: 533,953,678 | AVG: 27,135,799 <br /> MIN: 26,523,908 <br /> MAX: 47,992,925 | AVG: 16,471,741 <br /> MIN: 16,357,699 <br /> MAX: 16,550,967 |
| ov-Is-pkc-skc-aes4 (1000 executions) | m4f-flash | AVG: 306,038,171 <br /> MIN: 306,038,171 <br /> MAX: 306,038,171 | AVG: 13,042,381 <br /> MIN: 12,623,936 <br /> MAX: 23,216,797 | AVG: 7,591,366 <br /> MIN: 7,543,134 <br /> MAX: 7,624,981 |
| ov-Is-pkc-skc-aes4 (1000 executions) | m4f-flash-speed | AVG: 306,038,177 <br /> MIN: 306,038,177 <br /> MAX: 306,038,177 | AVG: 13,015,891 <br /> MIN: 12,623,929 <br /> MAX: 23,216,771 | AVG: 7,240,602 <br /> MIN: 6,370,144 <br /> MAX: 7,727,299 |
| ov-Is-pkc-skc-aes4 (1000 executions) | ref-flash | AVG: 525,507,933 <br /> MIN: 525,507,933 <br /> MAX: 525,507,933 | AVG: 18,926,161 <br /> MIN: 18,078,129 <br /> MAX: 39,547,158 | AVG: 8,025,255 <br /> MIN: 7,918,795 <br /> MAX: 8,117,551 |
