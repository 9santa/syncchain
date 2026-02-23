package rpc_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"syncchain/chain"
	"syncchain/rpc"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Fake balance for tests
type fakeBalanceChecker struct {
	balances map[chain.Address]uint64
}

func (f fakeBalanceChecker) Balance(acc chain.Address) (uint64, bool) {
	balance, ok := f.balances[acc]
	return balance, ok
}

// Test AccountCreate() rejects short password
func TestAccountCreateRejectsShortPassword(t *testing.T) {
	srv := rpc.NewAccountSrv(t.TempDir(), fakeBalanceChecker{})

	_, err := srv.AccountCreate(context.Background(), &rpc.AccountCreateReq{Password: "1234"})
	if err == nil {
		t.Fatal("expected error for short password")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected code %v, got %v", codes.InvalidArgument, st.Code())
	}
}

// Test AccountCreate() successfully persists account file
func TestAccountCreatePersistsAccountFile(t *testing.T) {
	keyStoreDir := t.TempDir()
	srv := rpc.NewAccountSrv(keyStoreDir, fakeBalanceChecker{})
	pass := "strong-password"

	res, err := srv.AccountCreate(context.Background(), &rpc.AccountCreateReq{Password: pass})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Address == "" {
		t.Fatal("excpected non-empty account address")
	}

	path := filepath.Join(keyStoreDir, res.Address)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("excpected persisted account file to exist: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected persisted account file to be non-empty")
	}
}

// Test AccountBalance() returns correct balance for existing account
func TestAccountBalanceReturnsBalanceForExistingAccount(t *testing.T) {
	addr := chain.Address("0xabc")
	srv := rpc.NewAccountSrv(t.TempDir(), fakeBalanceChecker{balances: map[chain.Address]uint64{addr: 55}})

	res, err := srv.AccountBalance(context.Background(), &rpc.AccountBalanceReq{Address: string(addr)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Balance != 55 {
		t.Fatalf("expected balance=55, got %d", res.Balance)
	}
}

// Test AccountBalance() returns NotFound for missing account
func TestAccountBalanceReturnsNotFoundForMissingAccount(t *testing.T) {
	srv := rpc.NewAccountSrv(t.TempDir(), fakeBalanceChecker{balances: map[chain.Address]uint64{}})

	_, err := srv.AccountBalance(context.Background(), &rpc.AccountBalanceReq{Address: "0xmissing"})
	if err == nil {
		t.Fatal("expected error for missing address balance request")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.NotFound {
		t.Fatalf("expected code %v, got %v", codes.NotFound, st.Code())
	}
}
