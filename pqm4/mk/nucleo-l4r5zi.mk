DEVICE=stm32l4r5zi

EXCLUDED_SCHEMES = \
  crypto_sign/ov-Is% \
	mupq/pqclean/crypto_kem/mceliece% \
  mupq/crypto_sign/falcon-1024-tree% \
  mupq/pqclean/crypto_sign/rainbow% \
  mupq/pqclean/%

DEVICES_DATA := ldscripts/devices.data

elf/boardtest.elf: CPPFLAGS+=-DSRAM_TIMING_TEST -DHAS_SRAM2 -DHAS_SRAM3
elf/boardtest.elf: LDSCRIPT=ldscripts/$(PLATFORM)-ramtest.ld

include mk/opencm3.mk
