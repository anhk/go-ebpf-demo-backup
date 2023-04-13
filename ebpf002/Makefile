export GOPROXY=https://goproxy.cn,direct
export GO111MODULE=on

OBJ = ebpf002
SRC = main.go ebpf_bpfel.go

all: $(OBJ)

$(OBJ):
	go mod tidy && go build -gcflags "-N -l" -o $@ ./$(SRC)
	@#cp -af $(OBJ) ./docker/

clean:
	rm -fr $(OBJ)

-include .deps
dep:
	echo -n "$(OBJ):" > .deps
	find src -name '*.go' | awk '{print $$0 " \\"}' >> .deps
	echo "" >> .deps