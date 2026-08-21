// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — gRPC Method Handlers (v4.3.1)
//
// handlers.go provides the gRPC MethodDesc entries for all 7 services
// (51 methods total). Since the platform uses hand-crafted Go structs
// with JSON tags (not protobuf-generated code), a custom JSON codec is
// registered with gRPC for wire serialization.
//
// Each method descriptor uses a reflection-based handler factory that:
//   1. Decodes the incoming JSON bytes into the request struct
//   2. Calls the typed service method
//   3. Encodes the response struct to JSON bytes
//
// This closes the gap where _grpcServiceDesc_* objects had empty
// MethodDesc slices, meaning gRPC knew the services existed but could
// not dispatch any RPC calls to them.

package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
)

// jsonCodec implements gRPC's encoding.Codec interface using
// encoding/json. This allows the hand-crafted Go structs (which use
// json struct tags) to be serialized on the gRPC wire format without
// requiring protobuf code generation.
type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return "json"
}

func init() {
	// Register the JSON codec so gRPC clients and servers can use
	// content-type "application/grpc+json".
	encoding.RegisterCodec(jsonCodec{})
}

// methodHandler creates a grpc.MethodHandler for a given service
// implementation and method name using reflection. The reqFactory
// function creates a new zero-value request struct of the correct
// type for the method.
func methodHandler(svc any, methodName string, reqFactory func() any) grpc.MethodHandler {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		// Create a new request struct of the correct type.
		req := reqFactory()

		// Decode the incoming message into the request struct.
		if err := dec(req); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "decode request: %v", err)
		}

		// If there's an interceptor, call it with a handler that
		// invokes the actual method.
		if interceptor != nil {
			info := &grpc.UnaryServerInfo{
				Server:     srv,
				FullMethod: methodName,
			}
			handler := func(ctx context.Context, req any) (any, error) {
				return invokeMethod(srv, ctx, methodName, req)
			}
			return interceptor(ctx, req, info, handler)
		}

		return invokeMethod(srv, ctx, methodName, req)
	}
}

// invokeMethod calls the named method on the service implementation
// using reflection. It looks up the method by name on the service's
// type and calls it with (ctx, req) arguments.
func invokeMethod(srv any, ctx context.Context, methodName string, req any) (resp any, err error) {
	// Recover from panics in the service method to prevent crashing
	// the gRPC server goroutine.
	defer func() {
		if r := recover(); r != nil {
			err = status.Errorf(codes.Internal, "method %s panicked: %v", methodName, r)
		}
	}()

	srvVal := reflect.ValueOf(srv)
	srvTyp := srvVal.Type()

	// Find the method by name.
	method, ok := srvTyp.MethodByName(methodName)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "method %s not found", methodName)
	}

	// Call the method: srv.Method(ctx, req)
	results := method.Func.Call([]reflect.Value{
		srvVal,
		reflect.ValueOf(ctx),
		reflect.ValueOf(req),
	})

	// Results should be (response, error).
	if len(results) != 2 {
		return nil, status.Errorf(codes.Internal, "method %s returned %d values, expected 2", methodName, len(results))
	}

	respVal := results[0]
	errVal := results[1]

	if errVal.IsNil() {
		return respVal.Interface(), nil
	}

	errInterface, ok := errVal.Interface().(error)
	if !ok {
		return nil, status.Errorf(codes.Internal, "method %s returned non-error error value", methodName)
	}

	return respVal.Interface(), errInterface
}

// buildMethodDescs creates a slice of grpc.MethodDesc from a
// serviceDesc, using reflection to create request factories.
// The svcImpl is used to look up the method signatures and create
// properly-typed request factories.
func buildMethodDescs(desc serviceDesc, svcImpl any) []grpc.MethodDesc {
	descs := make([]grpc.MethodDesc, len(desc.Methods))
	svcTyp := reflect.TypeOf(svcImpl)

	for i, m := range desc.Methods {
		// Find the method on the service implementation to get
		// the request type from its signature.
		method, ok := svcTyp.MethodByName(m.MethodName)
		if !ok {
			// This should never happen if serviceDesc and interface are in sync.
			panic(fmt.Sprintf("grpc: method %s not found on service %s", m.MethodName, desc.ServiceName))
		}

		// Method signature: func(srv, ctx, *RequestType) (*ResponseType, error)
		// The second argument (index 1 after the receiver) is the request type.
		reqType := method.Type.In(2) // 0=srv, 1=ctx, 2=req

		methodName := m.MethodName
		reqFactory := func() any {
			return reflect.New(reqType.Elem()).Interface()
		}

		descs[i] = grpc.MethodDesc{
			MethodName: methodName,
			Handler:    methodHandler(svcImpl, methodName, reqFactory),
		}
	}

	return descs
}

// replaceServiceDescs updates the internal _grpcServiceDesc_* objects
// with proper MethodDesc entries built from the service implementations.
// This is called from registerAllServices in server.go after each
// service implementation is created.
func replaceServiceDescs(server *grpc.Server, deps Dependencies, logger any) {
	_ = logger // reserved for future logging

	// Auth service
	var authSvc AuthServiceServer
	if deps.Auth != nil {
		authSvc = NewAuthService(deps.Auth, nil)
	} else {
		authSvc = &UnimplementedAuthServiceServer{}
	}
	authDescs := buildMethodDescs(AuthService_ServiceDesc, authSvc)
	_grpcServiceDesc_Auth.Methods = authDescs

	// Proxy service
	var proxySvc ProxyServiceServer
	if deps.Proxy != nil {
		proxySvc = NewProxyService(deps.Proxy, nil)
	} else {
		proxySvc = &UnimplementedProxyServiceServer{}
	}
	_grpcServiceDesc_Proxy.Methods = buildMethodDescs(ProxyService_ServiceDesc, proxySvc)

	// Compliance service
	var compSvc ComplianceServiceServer
	if deps.Compliance != nil {
		compSvc = NewComplianceService(deps.Compliance, nil)
	} else {
		compSvc = &UnimplementedComplianceServiceServer{}
	}
	_grpcServiceDesc_Compliance.Methods = buildMethodDescs(ComplianceService_ServiceDesc, compSvc)

	// SIEM service
	var siemSvc SIEMServiceServer
	if deps.SIEM != nil {
		siemSvc = NewSIEMService(deps.SIEM, nil)
	} else {
		siemSvc = &UnimplementedSIEMServiceServer{}
	}
	_grpcServiceDesc_SIEM.Methods = buildMethodDescs(SIEMService_ServiceDesc, siemSvc)

	// Webhook service
	var whSvc WebhookServiceServer
	if deps.Webhook != nil {
		whSvc = NewWebhookService(deps.Webhook, nil)
	} else {
		whSvc = &UnimplementedWebhookServiceServer{}
	}
	_grpcServiceDesc_Webhook.Methods = buildMethodDescs(WebhookService_ServiceDesc, whSvc)

	// Core service
	var coreSvc CoreServiceServer
	if deps.Metrics != nil {
		coreSvc = NewCoreService(deps.Metrics, nil)
	} else {
		coreSvc = &UnimplementedCoreServiceServer{}
	}
	_grpcServiceDesc_Core.Methods = buildMethodDescs(CoreService_ServiceDesc, coreSvc)

	// TLS service
	var tlsSvc TLSSvcServer
	if deps.TLS != nil {
		tlsSvc = NewTLSSvc(deps.TLS, nil)
	} else {
		tlsSvc = &UnimplementedTLSSvcServer{}
	}
	_grpcServiceDesc_TLS.Methods = buildMethodDescs(TLSSvc_ServiceDesc, tlsSvc)
}

// Ensure the unused import is referenced (debug used in recover).
var _ = debug.Stack
