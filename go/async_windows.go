// Copyright 2024 Lars-Christian Schulz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// #cgo CFLAGS: -I../include
// #include "snet/snet_cdefs.h"
// #include <Windows.h>
import "C"

import (
	"context"
	"errors"
	"runtime/cgo"
)

func callAsync(f func(context.Context) C.ScStatus, op *C.struct_ScAsyncOp) {
	ctx, cancel := context.WithCancel(context.Background())
	async := AsyncOp{
		cancel: cancel,
	}
	C.EnterCriticalSection(&op.crit)
	defer C.LeaveCriticalSection(&op.crit)
	op.handle = (C.uintptr_t)(cgo.NewHandle(async))
	op.result = C.SC_NOT_READY

	go func() {
		result := f(ctx)
		if errors.Is(ctx.Err(), context.Canceled) {
			result = C.SC_CANCELED
		}
		{
			C.EnterCriticalSection(&op.crit)
			defer C.LeaveCriticalSection(&op.crit)
			op.result = result
			cgo.Handle(op.handle).Delete()
			op.handle = 0
		}
		if op.callback != nil {
			C.call_completion_handler(op.callback, result, op.userdata)
		}
	}()
}

func cancelAsyncOp(op *C.struct_ScAsyncOp) {
	C.EnterCriticalSection(&op.crit)
	defer C.LeaveCriticalSection(&op.crit)
	if op.handle != 0 {
		h := cgo.Handle(op.handle)
		async := h.Value().(AsyncOp)
		async.cancel()
	}
}
