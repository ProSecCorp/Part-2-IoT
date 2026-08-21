CONTIKI_PROJECT = udp-client udp-server blackhole

all: $(CONTIKI_PROJECT)

CONTIKI=../..

CFLAGS += -DLOG_CONF_LEVEL_RPL=LOG_LEVEL_DBG
CFLAGS += -DBLACKHOLE_NODE

include $(CONTIKI)/Makefile.include