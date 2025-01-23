package auth

import (
	"context"

	"github.com/go-playground/validator"
	ssov1 "github.com/xcus33me/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)

	RegisterNewUser(
		LSctx context.Context,
		email string,
		password string,
	) (userID int64, err error)

	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth      Auth
	validator *validator.Validate
}

type LoginRequestDTO struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required,min=8"`
	AppID    int    `validate:"required"`
}

type RegisterRequestDTO struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required,min=8"`
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	dto := LoginRequestDTO{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		AppID:    int(req.AppId),
	}

	if err := s.validator.Struct(dto); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request: "+err.Error())
	}

	token, err := s.auth.Login(ctx, dto.Email, dto.Password, dto.AppID)
	if err != nil {
		// TODO

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	req *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	dto := RegisterRequestDTO{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}

	if err := s.validator.Struct(dto); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request: "+err.Error())
	}

	userID, err := s.auth.RegisterNewUser(ctx, dto.Email, dto.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{
		UserId: userID,
	}, nil
}

func (s *serverAPI) IsAdmin(
	ctx context.Context,
	req *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	panic("not implemented")
}
