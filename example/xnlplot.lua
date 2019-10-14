#!/usr/bin/env lua

require "ubus"
require "uloop"

uloop.init()

local conn = ubus.connect()
if not conn then
   error("Can't connect to ubus")
end

local tstatus = conn:call("xdpnetload", "status", { })

if not tstatus then
   error("Can't get status (xdpnetload is not running?)")
end

local status = {}

for k, v in pairs(tstatus) do
--   print("key=" .. k .. " value=" .. tostring(v))
   status[k] = v
end

local interval = status["interval"] + 0
local num_filters = status["num_filters"] + 0
local filters = {}

if interval <= 0 or num_filters <= 0 then
   error("Incorrect status")
end

local datafiles = {}

for i=0,num_filters-1 do
   filters[i] = status["rule."..i]

   if not filters[i] then
      error("Filter " .. i .. " is undefined")
   end

   datafiles[i] = io.open("rule"..i..".data" ,"w")
   datafiles[i]:setvbuf('line')

   local titlef = io.open("rule"..i..".data.title" ,"w")
   titlef:write("\""..filters[i].."\"\n")
   titlef:close()
end

local process_event = {
   xdpnetload = function(msg)
      local i = 0

      for _, v in pairs(msg) do
	 local ts = v["time"]
	 local cur_rate = v["current_mbps"]

	 -- print(i .. ": " .. ts .. " " .. cur_rate)
	 datafiles[i]:write(ts, " ", cur_rate, "\n")
	 datafiles[i]:flush()
	 i = i+1
      end
   end,
}

conn:listen(process_event)

uloop.run()

conn:close()