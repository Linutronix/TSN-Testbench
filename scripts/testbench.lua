--
-- Copyright (C) 2024 Linutronix GmbH
-- Author Kurt Kanzenbach <kurt@linutronix.de>
--
-- SPDX-License-Identifier: BSD-2-Clause
--
testbench_proto = Proto("Testbench", "Linux TSN Testbench Protocol")

frame_id = ProtoField.uint16("Testbench.FrameId", "frame_id", base.HEX)
frame_counter = ProtoField.uint32("Testbench.FrameCounter", "frame_counter", base.DEC)
cycle_counter = ProtoField.uint32("Testbench.CycleCounter", "cycle_counter", base.DEC)
tx_timestamp = ProtoField.uint64("Testbench.TxTimestamp", "tx_timestamp", base.DEC)

testbench_proto.fields = { frame_id, frame_counter, cycle_counter, tx_timestamp }

function testbench_proto.dissector(buffer, pinfo, tree)
   length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = testbench_proto.name

   local id = buffer(0, 2):uint()
   local frame = buffer(2, 4):uint()
   local cycle = buffer(6, 4):uint()

   local traffic_class = "Unknown"
   if id == 0x0100 then traffic_class = "TSN High" end
   if id == 0x0200 then traffic_class = "TSN Low" end
   if id == 0x8000 then traffic_class = "RTC" end
   if id == 0xfc01 then traffic_class = "RTA" end
   if id == 0xfefe then traffic_class = "DCP" end

   pinfo.cols.info = traffic_class .. " | Frame: " .. frame .. " Cycle: " .. cycle

   local subtree = tree:add(testbench_proto, buffer(), "Testbench MetaData")
   subtree:add(frame_id, buffer(0, 2))
   subtree:add(frame_counter, buffer(2, 4))
   subtree:add(cycle_counter, buffer(6, 4))
   subtree:add(tx_timestamp, buffer(10, 8))
end

local ether_table = DissectorTable.get("ethertype")
ether_table:add(0x8892, testbench_proto)
