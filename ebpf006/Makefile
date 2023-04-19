export GOPROXY=https://goproxy.cn,direct
export GO111MODULE=on

OBJ = ebpf006
SRC = main.go ebpf_bpfel.go

all: generate $(OBJ)

$(OBJ): $(SRC)
	go mod tidy && go build -gcflags "-N -l" -o ${OBJ} ./$(SRC)

generate: ebpf_bpfel.o
ebpf_bpfel.o ebpf_bpfel.go: ebpf.c
	go generate

clean:
	rm -fr $(OBJ)

-include .deps
dep:
	echo -n "$(OBJ):" > .deps
	find . -name '*.go' | awk '{print $$0 " \\"}' >> .deps
	echo "" >> .deps
