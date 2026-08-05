package gate

# The reason carries the data document, so a verdict proves both the
# module and the data reached the engine.
verdict := {
	"decision": "allow",
	"reason": sprintf("tier=%v", [data.tier]),
}
