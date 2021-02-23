// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIB_FIDL_LLCPP_SERVER_H_
#define LIB_FIDL_LLCPP_SERVER_H_

#include <lib/fidl/llcpp/async_binding.h>
#include <lib/fidl/llcpp/internal/server_details.h>
#include <lib/fidl/llcpp/server_end.h>

namespace fidl {

// |BindServer| starts handling message on |server_end| using implementation
// |impl|, on a potentially multi-threaded |dispatcher|. Multiple requests may
// be concurrently in-flight, and responded to synchronously or asynchronously.
//
// |ServerImpl| should implement the abstract base class
// |llcpp::library::MyProtocol::Interface|, typically generated by the low-level
// C++ backend, corresponding to methods in the protocol |library.MyProtocol|.
//
// This function adds an asynchronous wait to the given |dispatcher| for new
// messages to arrive on |server_end|. When each message arrives, the
// corresponding method handler in |ServerImpl| is called on one of the
// threads of the |dispatcher|.
//
// ## Starting message dispatch
//
// On success, |BindServer| associates |impl| and |server_end| with the
// |dispatcher|, and begins handling messages that arrive on |server_end|. This
// association is called a "binding". The dispatcher owns the |server_end| while
// the binding is active.
//
// The returned |ServerBindingRef| is a reference to the binding; it does not
// own the binding. In particular, the binding is kept alive by the dispatcher
// even if the returned |fit::result<ServerBindingRef>| is dropped. If the
// binding reference is ignored, the server operates in a "self-managed" mode,
// where it will continue listening for messages until an error occurs or if the
// user tears down the connection using a |Completer|.
//
// If an error occurs when creating the binding, |BindServer| returns a
// |fit::error| and |server_end| is closed.
//
// ## Stopping message dispatch
//
// ### Unbind
//
// |ServerBindingRef::Unbind| requests to explicitly disassociate the server
// |impl| and endpoint from the dispatcher, and to retrieve the |server_end|
// endpoint. Note that this is an asynchronous procedure.
//
// |Unbind| is guaranteed to return in a short and bounded amount of time. It
// does not depend on whether there are any in-flight requests. As such, the
// user may safely take locks around an |Unbind| call.
//
// After unbinding completes:
//
// - The |server_end| is detached from the dispatcher; no dispatcher threads
//   will interact with it.
// - Calls on |Completer| objects from in-flight requests will have no effect.
//   Failable operations will return |ZX_ERR_CANCELED|.
// - Subsequent calls made on the |ServerBindingRef| will be ignored. Failable
//   operations will return |ZX_ERR_CANCELED|.
// - If |on_unbound| is not specified, the |server_end| is closed.
// - If |on_unbound| is specified, it will be called to signal the completion.
//   Ownership of the |server_end| is transferred to this hook.
//
// |on_unbound| must be a callable of the following signature:
//
//     // |impl| is the pointer to the server implementation.
//     // |info| contains the reason for stopping the message dispatch.
//     // |server_end| is the server channel endpoint.
//     // |ProtocolType| is the type of the FIDL protocol.
//     void OnUnbound(ServerImpl* impl,
//                    fidl::UnbindInfo info,
//                    fidl::ServerEnd<ProtocolType> server_end);
//
// More precisely, if there is a dispatcher thread waiting for incoming messages
// on the channel, it will stop monitoring the channel and detach itself from
// the binding. If there is a thread executing the method handler, the channel
// would be pulled from underneath it, such that it may no longer make any
// replies. When no thread has any active reference to the channel, the
// |on_unbound| callback will be invoked.
//
// |on_unbound| will be executed on a |dispatcher| thread, unless the user shuts
// down the |dispatcher| while there are active bindings associated with it. In
// that case, those bindings will be synchronously unbound, and the |on_unbound|
// callback would be executed on the thread invoking shutdown. |on_unbound|
// hooks must not acquire any locks that could be held during |dispatcher|
// shutdown.
//
// ### Close
//
// |ServerBindingRef::Close| has the same effects as |Unbind| except that it
// sends an epitaph message on the |server_end|.
//
// If specified, the |on_unbound| hook will execute after the epitaph has been
// sent.
//
// ## Server implementation ownership
//
// The server instance |impl| must remain alive while it is bound to the message
// dispatcher. Take special note of |Unbind|, as it returns before the unbind
// operation has completed. It is only safe to destroy the server instance
// within or after |on_unbound|.
//
// This overload borrows the server implementation by raw pointer. There are
// additional overloads of |BindServer| that either takes ownership of an
// implementation via |std::unique_ptr|, or shares the ownership via
// |std::shared_ptr|. Using either of those smart pointer overloads would
// automatically ensure memory safety.
//
// ## Error conditions
//
// The server implementation can call |Close| on the completer to indicate an
// application error during message handling.
//
// The connection will also be automatically closed by the dispatching logic in
// certain conditions:
//
// - If the client-end of the channel is closed (PEER_CLOSED).
// - If an error occurs when waiting on, reading from, or writing to the
//   channel.
// - If decoding an incoming message fails or encoding an outgoing message
//   fails.
// - If the message was not defined in the FIDL protocol.
//
// These error conditions lead to the unbinding of the connection. If
// |on_unbound| was specified, it would be called on a |dispatcher| thread with
// a failure reason, allowing the user to process the error.
//
// ## Message ordering
//
// By default, the message dispatch function for a binding will only ever be
// invoked by a single |dispatcher| thread at a time, even if the dispatcher has
// multiple threads. Messages will be dispatched in the order that they are
// received on the channel.
//
// A method handler may call |EnableNextDispatch| on their completer to allow
// another thread to begin dispatching the next message before the current
// method handler returns. Of course, this is only meaningful if the
// |dispatcher| has multiple threads.
//
// If a particular user does not care about ordering, they may invoke
// |EnableNextDispatch| immediately in the message handler. If you have such a
// use case, please file a bug, where we may consider instead providing a mode
// to automatically parallelize.
//
// ## Template Ergonomics
//
// This function is able to infer the type of |ServerImpl| and |OnUnbound| in
// most cases. The following code would compile without explicitly specializing
// |BindServer|:
//
//     // Suppose |this| is a server implementation class |Foo|, that
//     // implements the |Bar| FIDL protocol.
//     fidl:ServerEnd<Bar> server_end = ...;
//     fidl::BindServer(dispatcher, std::move(server_end), this,
//                      [](Foo*, fidl::UnbindInfo, fidl::ServerEnd<Bar>) { ... });
//
// TODO(fxbug.dev/67062): |fidl::BindServer| and associated API should return a
// |zx::status|. TODO(fxbug.dev/66343): Consider using a "DidUnbind" virtual
// function in the server interface to replace the |on_unbound| handler lambda.
template <typename ServerImpl, typename OnUnbound = std::nullptr_t>
fit::result<ServerBindingRef<typename ServerImpl::_EnclosingProtocol>, zx_status_t> BindServer(
    async_dispatcher_t* dispatcher,
    fidl::ServerEnd<typename ServerImpl::_EnclosingProtocol> server_end, ServerImpl* impl,
    OnUnbound&& on_unbound = nullptr) {
  return internal::BindServerImpl<ServerImpl>(
      dispatcher, std::move(server_end), impl,
      internal::UnboundThunk(std::move(impl), std::forward<OnUnbound>(on_unbound)));
}

// Overload of |BindServer| that takes ownership of the server as a |unique_ptr|.
// The pointer is destroyed on the same thread as the one calling |on_unbound|,
// and happens right after |on_unbound|. See |BindServer| for details.
template <typename ServerImpl, typename OnUnbound = std::nullptr_t>
fit::result<ServerBindingRef<typename ServerImpl::_EnclosingProtocol>, zx_status_t> BindServer(
    async_dispatcher_t* dispatcher,
    fidl::ServerEnd<typename ServerImpl::_EnclosingProtocol> server_end,
    std::unique_ptr<ServerImpl>&& impl, OnUnbound&& on_unbound = nullptr) {
  ServerImpl* impl_raw = impl.get();
  return internal::BindServerImpl<ServerImpl>(
      dispatcher, std::move(server_end), impl_raw,
      internal::UnboundThunk(std::move(impl), std::forward<OnUnbound>(on_unbound)));
}

// Overload of |BindServer| that shares ownership of the server via a |shared_ptr|.
// The pointer is destroyed on the same thread as the one calling |on_unbound|,
// and happens right after |on_unbound|. See |BindServer| for details.
template <typename ServerImpl, typename OnUnbound = std::nullptr_t>
fit::result<ServerBindingRef<typename ServerImpl::_EnclosingProtocol>, zx_status_t> BindServer(
    async_dispatcher_t* dispatcher,
    fidl::ServerEnd<typename ServerImpl::_EnclosingProtocol> server_end,
    std::shared_ptr<ServerImpl> impl, OnUnbound&& on_unbound = nullptr) {
  ServerImpl* impl_raw = impl.get();
  return internal::BindServerImpl<ServerImpl>(
      dispatcher, std::move(server_end), impl_raw,
      internal::UnboundThunk(std::move(impl), std::forward<OnUnbound>(on_unbound)));
}

// This class manages a server connection and its binding to an
// |async_dispatcher_t*|, which may be multi-threaded. See the detailed
// documentation on the |BindServer| APIs.
template <typename Protocol>
class ServerBindingRef {
 public:
  ~ServerBindingRef() = default;

  ServerBindingRef(ServerBindingRef&&) noexcept = default;
  ServerBindingRef& operator=(ServerBindingRef&&) noexcept = default;

  ServerBindingRef(const ServerBindingRef&) = default;
  ServerBindingRef& operator=(const ServerBindingRef&) = default;

  // Triggers an asynchronous unbind operation. If specified, |on_unbound| will be invoked on a
  // dispatcher thread, passing in the channel and the unbind reason. On return, the dispatcher
  // will no longer have any wait associated with the channel (though handling of any already
  // in-flight transactions will continue).
  //
  // This may be called from any thread.
  //
  // WARNING: While it is safe to invoke Unbind() from any thread, it is unsafe to wait on the
  // OnUnboundFn from a dispatcher thread, as that will likely deadlock.
  void Unbind() {
    if (auto binding = event_sender_.binding_.lock())
      binding->Unbind(std::move(binding));
  }

  // Triggers an asynchronous unbind operation. Eventually, the epitaph will be sent over the
  // channel which will be subsequently closed. If specified, |on_unbound| will be invoked giving
  // the unbind reason as an argument.
  //
  // This may be called from any thread.
  void Close(zx_status_t epitaph) {
    if (auto binding = event_sender_.binding_.lock())
      binding->Close(std::move(binding), epitaph);
  }

  // Return the interface for sending FIDL events. If the server has been unbound, calls on the
  // interface return error with status ZX_ERR_CANCELED.
  const typename Protocol::WeakEventSender* get() const { return &event_sender_; }
  const typename Protocol::WeakEventSender* operator->() const { return &event_sender_; }
  const typename Protocol::WeakEventSender& operator*() const { return event_sender_; }

 private:
  // This is so that only |BindServerTypeErased| will be able to construct a
  // new instance of |ServerBindingRef|.
  friend fit::result<ServerBindingRef<Protocol>, zx_status_t>
  internal::BindServerTypeErased<Protocol>(async_dispatcher_t* dispatcher,
                                           fidl::ServerEnd<Protocol> server_end,
                                           internal::IncomingMessageDispatcher* interface,
                                           internal::AnyOnUnboundFn on_unbound);

  explicit ServerBindingRef(std::weak_ptr<internal::AsyncServerBinding<Protocol>> internal_binding)
      : event_sender_(std::move(internal_binding)) {}

  typename Protocol::WeakEventSender event_sender_;
};

}  // namespace fidl

#endif  // LIB_FIDL_LLCPP_SERVER_H_
