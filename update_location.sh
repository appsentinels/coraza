#for updating the locations inside the coraza directory to change their reference --later  we may want to avoid these 2 
#	coreruleset "github.com/appsentinels/coraza-coreruleset"
#	crstests "github.com/appsentinels/coraza-coreruleset/tests"
find . -type f -exec sed -i 's|github.com/appsentinels/coraza|github.com/appsentinels/coraza|' {} +

