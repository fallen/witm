NAME = witm
CFLAGS += -g -Wall -Wextra -O3 `pcap-config --cflags` `dnet-config --cflags`
LDLIBS += `pcap-config --libs` `dnet-config --libs`

SRC = $(NAME).c got_packet.c forward.c arp.c plugins.c
OBJ = $(SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)

$(OBJ): $(NAME).h

clean:
	rm -f $(OBJ)

distclean: clean
	rm -f $(NAME)

re: distclean all
