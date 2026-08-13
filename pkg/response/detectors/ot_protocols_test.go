// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - OT/ICS Protocol Detection Tests
// =========================================================================

package detectors

import (
	"testing"
)

func TestDetectOTProtocols_ModbusFunctionCode(t *testing.T) {
	text := "Set function code 05 to force the coil"
	matches := DetectOTProtocols(text)
	if len(matches) == 0 {
		t.Fatal("Expected Modbus function code detection")
	}
	if matches[0].Category != "ot_modbus_function_code" {
		t.Errorf("Expected ot_modbus_function_code, got %s", matches[0].Category)
	}
}

func TestDetectOTProtocols_ModbusWriteSingleCoil(t *testing.T) {
	text := "Using FC 05 to write single coil"
	matches := DetectOTProtocols(text)
	if len(matches) == 0 {
		t.Fatal("Expected Modbus write single coil detection")
	}
	found := false
	for _, m := range matches {
		if m.Category == "ot_modbus_write_single_coil" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected ot_modbus_write_single_coil pattern")
	}
}

func TestDetectOTProtocols_ModbusWriteMultipleRegisters(t *testing.T) {
	text := "Function code 16 to write multiple registers"
	matches := DetectOTProtocols(text)
	if len(matches) == 0 {
		t.Fatal("Expected Modbus write multiple registers detection")
	}
	found := false
	for _, m := range matches {
		if m.Category == "ot_modbus_write_multiple_registers" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected ot_modbus_write_multiple_registers pattern")
	}
}

func TestDetectOTProtocols_DNP3ControlRelay(t *testing.T) {
	text := "DNP3 relay output block 12 command"
	matches := DetectOTProtocols(text)
	if len(matches) == 0 {
		t.Fatal("Expected DNP3 control relay detection")
	}
	found := false
	for _, m := range matches {
		if m.Category == "ot_dnp3_control_relay" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected ot_dnp3_control_relay pattern")
	}
}

func TestDetectOTProtocols_DNP3AnalogOutput(t *testing.T) {
	text := "Set DNP3 analog output block 41 to new setpoint"
	matches := DetectOTProtocols(text)
	if len(matches) == 0 {
		t.Fatal("Expected DNP3 analog output detection")
	}
	found := false
	for _, m := range matches {
		if m.Category == "ot_dnp3_analog_output" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected ot_dnp3_analog_output pattern")
	}
}

func TestDetectOTProtocols_OPCUAMethodCall(t *testing.T) {
	text := "OPC-UA method Server.Diagnostics.GetStatus"
	matches := DetectOTProtocols(text)
	if len(matches) == 0 {
		t.Fatal("Expected OPC-UA method call detection")
	}
	found := false
	for _, m := range matches {
		if m.Category == "ot_opcua_method_call" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected ot_opcua_method_call pattern")
	}
}

func TestDetectOTProtocols_OPCUAWriteValue(t *testing.T) {
	text := "Execute WriteValue method on the node"
	matches := DetectOTProtocols(text)
	if len(matches) == 0 {
		t.Fatal("Expected OPC-UA WriteValue detection")
	}
	found := false
	for _, m := range matches {
		if m.Category == "ot_opcua_write_value" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected ot_opcua_write_value pattern")
	}
}

func TestDetectOTProtocols_NoMatch(t *testing.T) {
	text := "Normal industrial automation text without protocol commands"
	matches := DetectOTProtocols(text)
	if len(matches) != 0 {
		t.Errorf("Expected no matches, got %d", len(matches))
	}
}

func TestDetectOTProtocols_MixedContent(t *testing.T) {
	text := `
		Industrial control scenario:
		1. Modbus function code 05 for coil control
		2. DNP3 relay output block 12 for grid switching
		3. OPC-UA Server.Control.StartProcess
	`
	matches := DetectOTProtocols(text)
	if len(matches) < 3 {
		t.Errorf("Expected at least 3 matches, got %d", len(matches))
	}
}
