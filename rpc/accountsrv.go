package rpc

import (
	"context"
	"fmt"
	"syncchain/chain"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AccountSrv struct {
	keyStoreDir string
	balChecker  BalanceChecker
}

type BalanceChecker interface {
	Balance(acc chain.Address) (uint64, bool)
}

func NewAccountSrv(keyStoreDir string, balChecker BalanceChecker) *AccountSrv {
	return &AccountSrv{keyStoreDir: keyStoreDir, balChecker: balChecker}
}

/*
Validate the owner's password
Create a new account
Persist the generated account key pair to the local store of the node
*/
func (s *AccountSrv) AccountCreate(ctx context.Context, req *AccountCreateReq) (*AccountCreateRes, error) {
	pass := []byte(req.Password)
	if len(pass) < 5 {
		return nil, status.Errorf(codes.InvalidArgument, "password length is less than 5")
	}
	acc, err := chain.NewAccount()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	err = acc.WriteAccount(s.keyStoreDir, pass)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	res := &AccountCreateRes{Address: string(acc.Adress())}
	return res, nil
}

// Check the balance of the account address
func (s *AccountSrv) AccountBalance(ctx context.Context, req *AccountBalanceReq) (*AccountBalanceRes, error) {
	acc := req.Address
	balance, exists := s.balChecker.Balance(acc)
	if !exists {
		return nil, codes.NotFound, fmt.Sprintf("account %v does not exist or has not made any transaction yet", acc)
	}
	res := AccountBalanceRes{Balance: balance}
	return res, nil
}
