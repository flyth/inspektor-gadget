acc = nil
wr = nil
ds = nil
metrics = nil
metricsField = nil
metricsField2 = nil
events = 0
ticker = 0

function init(ctx)
    ctx:Log("Hello from Lua")
    ds = ctx:GetDataSource("exec")
--     ds:AddAnnotation("view.maxRows", "5")
--     ds:AddAnnotation("view.hidden", "true")

--     nds = ctx:AddDataSource("foo")
--     nds:AddAnnotation("view.maxRows", "5")
--     ndsField = nds:AddField("hooray", Kind_String)

--    acc = ds:GetField("args")
    wr = ds:AddField("luaval", Kind_String)

    metrics = ctx:AddDataSource("metrics")
--    metrics:AddAnnotation("view.maxRows", "5")
    metrics:AddAnnotation("metrics.name", "demo")
    metrics:AddAnnotation("metrics.enabled", "true")
    metrics:AddAnnotation("metrics.realtime", "true")
    metricsField = metrics:AddField("ctr", Kind_Int32)
--    metricsField2 = metrics:AddField("ticker", Kind_Int32)

    newTicker(1000, "tick")
end

function preStart(ctx)
    ds:Subscribe("yeah")
end

function start(ctx)

end

function stop(ctx)
--[[     local ndata = nds:NewData()
    ndsField:SetString(ndata, ""..events.." events")
    nds:EmitAndRelease(ndata) ]]

    ctx:Log("bye from lua")
end

function tick()
--     local ndata = nds:NewData()
--    ticker = ticker+1
--    ndsField:SetString(ndata, "ticker event: "..ticker)
--    nds:EmitAndRelease(ndata)

    local ndata = metrics:NewData()
    metricsField:SetInt(ndata, events)
--    metricsField2:SetInt(ndata, ticker)
    metrics:EmitAndRelease(ndata)

--     for i = 1, 40 do
--         local ndata = nds:NewData()
--         ndsField:SetString(ndata, ""..events.." events")
--         nds:EmitAndRelease(ndata)
--     end
end

function yeah(ds, data)
--[[     local str = acc:GetString(data)
    wr:SetString(data, "lua:"..str) ]]

    events = events + 1

    wr:SetString(data, "blah")
end