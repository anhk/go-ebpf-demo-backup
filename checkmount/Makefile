export GOPROXY=https://goproxy.cn,direct
export GO111MODULE=on

OBJ = checkmount
SRC = 

all: $(OBJ)

$(OBJ): 
	go mod tidy && go build -gcflags "-N -l" -o ${OBJ} ./$(SRC)

clean:
	rm -fr $(OBJ)

-include .deps
dep:
	echo -n "$(OBJ):" > .deps
	find . -name '*.go' | awk '{print $$0 " \\"}' >> .deps
	echo "" >> .deps