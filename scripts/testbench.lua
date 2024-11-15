--
-- Copyright (C) 2024 Linutronix GmbH
-- Author Kurt Kanzenbach <kurt@linutronix.de>
--
-- SPDX-License-Identifier: BSD-2-Clause
--
testbench_proto = Proto("Testbench", "Linux TSN Testbench Protocol")

-- MetaData valid for all frames
frame_id = ProtoField.uint16("Testbench.FrameId", "frame_id", base.HEX)
frame_counter = ProtoField.uint32("Testbench.FrameCounter", "frame_counter", base.DEC)
cycle_counter = ProtoField.uint32("Testbench.CycleCounter", "cycle_counter", base.DEC)
tx_timestamp = ProtoField.uint64("Testbench.TxTimestamp", "tx_timestamp", base.DEC)

-- SecurityMetaData only valid for secured frames
sec_info = ProtoField.uint8("Testbench.SecInfo", "sec_info", base.HEX)
sec_control = ProtoField.uint8("Testbench.SecControl", "sec_control", base.HEX)
sec_sequence_counter = ProtoField.uint32("Testbench.SecSequenceCounter", "sec_sequence_counter", base.DEC)
sec_length = ProtoField.uint16("Testbench.SecLength", "sec_length", base.DEC)
sec_checksum = ProtoField.bytes("Testbench.SecChecksum", "sec_checksum")

testbench_proto.fields = { frame_id, frame_counter, cycle_counter, tx_timestamp,
			   sec_info, sec_control, sec_sequence_counter, sec_length, sec_checksum }

function testbench_proto.dissector(buffer, pinfo, tree)
   local length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = testbench_proto.name

   local id = buffer(0, 2):uint()
   local frame
   local cycle

   local sec = false
   local traffic_class = "Unknown"
   if id == 0x0100 then traffic_class = "TSN High" end
   if id == 0x0200 then traffic_class = "TSN Low" end
   if id == 0x8000 then traffic_class = "RTC" end
   if id == 0xfc01 then traffic_class = "RTA" end
   if id == 0xfefe then traffic_class = "DCP" end

   if id == 0x0101 then
      traffic_class = "TSN High Sec"
      sec = true
   end

   if id == 0x0201 then
      traffic_class = "TSN Low Sec"
      sec = true
   end

   if id == 0x8001 then
      traffic_class = "RTC Sec"
      sec = true
   end

   if id == 0xfc02 then
      traffic_class = "RTA Sec"
      sec = true
   end

   if sec then
      frame = buffer(10, 4):uint()
      cycle = buffer(14, 4):uint()
   else
      frame = buffer(2, 4):uint()
      cycle = buffer(6, 4):uint()
   end

   pinfo.cols.info = traffic_class .. " | Frame: " .. frame .. " Cycle: " .. cycle

   local subtree = tree:add(testbench_proto, buffer(), "Testbench MetaData")
   if sec then
      subtree:add(frame_id, buffer(0, 2))
      subtree:add(sec_info, buffer(2, 1))
      subtree:add(sec_control, buffer(3, 1))
      subtree:add(sec_sequence_counter, buffer(4, 4))
      subtree:add(sec_length, buffer(8, 2))
      subtree:add(frame_counter, buffer(10, 4))
      subtree:add(cycle_counter, buffer(14, 4))
      subtree:add(tx_timestamp, buffer(18, 8))
      subtree:add(sec_checksum, buffer(length - 16, 16))
   else
      subtree:add(frame_id, buffer(0, 2))
      subtree:add(frame_counter, buffer(2, 4))
      subtree:add(cycle_counter, buffer(6, 4))
      subtree:add(tx_timestamp, buffer(10, 8))
   end
end

local ether_table = DissectorTable.get("ethertype")
ether_table:add(0x8892, testbench_proto)
