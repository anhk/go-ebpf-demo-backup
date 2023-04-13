export GOPROXY=https://goproxy.cn,direct
export GO111MODULE=on

OBJ = ebpf003
SRC = main.go ebpf_bpfel.go

all: $(OBJ)

$(OBJ): generate
	go mod tidy && go build -gcflags "-N -l" -o $@ ./$(SRC)
	@#cp -af $(OBJ) ./docker/

generate: ebpf.c 
	go generate

clean:
	rm -fr $(OBJ)

-include .deps
dep:
	echo -n "$(OBJ):" > .deps
	find . -name '*.go' | awk '{print $$0 " \\"}' >> .deps
	echo "" >> .deps