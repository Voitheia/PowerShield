#PowerShield v1.0 5/25/2021
#Rob Shovan https://github.com/Voitheia/
#About: Fast Windows OS security patches for use in cybersecurity competitions.

# +---------------------------- USERS ----------------------------+

#automatic password changing of Administrator
$admin = Create-Password

#I need to make sure this works the way I think it will
net user Administrator $admin

#choose between disabling all other users or changing all other user's passwords

#create backup admin account
$backup = Create-Password
New-LocalUser "HiRedTeam" -Password $backup -Description "Red team is the best!"
Add-LocalGroupMember -Group "Administrators" -Member "HiRedTeam"

#disable guest account
net user guest /active:no

# +---------------------------- SMB ----------------------------+

#disable smbv1 with powershell one liners and registry key changes
#is there a way or is it necessary to make other smb versions more secure?

Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $false

#need to find registry key locations for smbv1

# +---------------------------- RDP ----------------------------+

#some basic rdp security through registry key edits
#needs some more research to see if we can find more

#sets a few things in gp for rdp
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -Value 1

#rdp remote credential guard
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD

# +---------------------------- MIMIKATZ ----------------------------+

#some basic mimikatz defence through registry key edits
#needs some more research to see if we can find more

reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v Negotiate /t REG_DWORD /d 0


# +---------------------------- SERVICES ----------------------------+

#disable some common unnecessary services
#format: Set-Service -name "SERVICE-NAME" -Status stopped -force
Set-Service -name "spooler" -Status stopped -force
Set-Service -name "TelnetServer" -Status stopped -force

# +---------------------------- SYSINTERNALS ----------------------------+

#these need to be changed so they target the system path of the user running the script

#download autoruns, tcpview, psexp and procmon
Invoke-WebRequest https://download.sysinternals.com/files/ProcessMonitor.zip -OutFile "C:\Users\Administrator\Downloads\ProcessMonitor.zip"
Invoke-WebRequest https://download.sysinternals.com/files/ProcessExplorer.zip -OutFile "C:\Users\Administrator\Downloads\ProcessExplorer.zip"
Invoke-WebRequest https://download.sysinternals.com/files/Autoruns.zip -OutFile "C:\Users\Administrator\Downloads\Autoruns.zip"
Invoke-WebRequest https://download.sysinternals.com/files/TCPView.zip -OutFile "C:\Users\Administrator\Downloads\TCPView.zip"

#extract them
Expand-Archive -Path "C:\Users\Administrator\Downloads\ProcessMonitor.zip" -DestinationPath "C:\Users\Administrator\Downloads\ProcessMonitor"
Expand-Archive -Path "C:\Users\Administrator\Downloads\ProcessExplorer.zip" -DestinationPath "C:\Users\Administrator\Downloads\ProcessExplorer"
Expand-Archive -Path "C:\Users\Administrator\Downloads\Autoruns.zip" -DestinationPath "C:\Users\Administrator\Downloads\Autoruns"
Expand-Archive -Path "C:\Users\Administrator\Downloads\TCPView.zip" -DestinationPath "C:\Users\Administrator\Downloads\TCPView"

#back them up
Copy-Item -Path "C:\Users\Administrator\Downloads\ProcessMonitor\*" -Destination "C:\Windows\Cursors\dankmemeshere\"
Copy-Item -Path "C:\Users\Administrator\Downloads\ProcessExplorer\*" -Destination "C:\Windows\Cursors\dankmemeshere\"
Copy-Item -Path "C:\Users\Administrator\Downloads\Autoruns\*" -Destination "C:\Windows\Cursors\dankmemeshere\"
Copy-Item -Path "C:\Users\Administrator\Downloads\TCPView\*" -Destination "C:\Windows\Cursors\dankmemeshere\"

# +---------------------------- STUFF YOU MIGHT NOT WANT TO DO ----------------------------+

#disable admin account
$flagboi1 = Read-Host "enter 1 to disable default admin"
if($flagboi1 -eq 1){
net user Administrator /active:no
}

#nuke task scheduler
$flagboi2 = Read-Host "enter 1 to nuke task scheduler"
if($flagboi2 -eq 1){
Remove-Item 'C:\Windows\System32\Tasks'
}

# +---------------------------- EXECUTION POLICY ----------------------------+

#configure powershell execution policy

[Environment]::SetEnvironmentVariable(‘__PSLockdownPolicy‘, ‘4’, ‘Machine‘)

# +---------------------------- RESTART ----------------------------+
Restart-Computer

# +---------------------------- FUNCTION ----------------------------+
#need to have a function that handles the randomization of passwords based on time and a given int
Function Create-Password {

    #giant array of words to choose from
    $wordList = @('gull','ferret','locust','planarian','lion','puffin','condor','haddock','sheep','donkey','lizard','quokka','boar','rodent','cattle','shrew','antlion','vole','cicada','donkey','ferret','panda','albatross','mastodon','beaver','bedbug','jellyfish','meerkat','guineafowl','panther','mink','alpaca','mongoose','ape','bat','silkworm','cobra','impala','lamprey','horse','quelea','lion','muskox','wombat','badger','owl','moose','toad','shark','squirrel','aphid','mosquito','rodent','vole','raven','orca','locust','parrot','lemming','marmoset','wombat','pig','opossum','puma','pig','llama','clownfish','falcon','coyote','anaconda','spider','goat','quelea','platypus','turtle','caribou','mongoose','horse','ocelot','tiger','marlin','cougar','prawn','roundworm','shark','bovid','koala','jackal','bovid','scallop','primate','gamefowl','ladybug','chinchilla','hyena','muskox','parakeet','stoat','yak','cardinal','finch','koala','otter','stork','slug','worm','puffin','partridge','parrot','marsupial','narwhal','mule','rabbit','hookworm','alpaca','hamster','sparrow','piranha','yak','armadillo','antelope','gerbil','swordtail','moth','salmon','cat','donkey','skink','gayal','octopus','raccoon','cat','parakeet','parakeet','rhinoceros','sheep','flea','smelt','cobra','antelope','cockroach','shrimp','toucan','mammal','slug','lion','cobra','nightingale','silkworm','tapir','vole','cow','lamprey','egret','mackerel','gecko','wolverine','mule','gorilla','jay','rabbit','mosquito','snake','sturgeon','bass','reptile','clownfish','weasel','sheep','finch','catfish','marten','cicada','boar','loon','pelican','woodpecker','alligator','monkey','dinosaur','fly','tarsier','alpaca','aardwolf','capybara','spoonbill','crawdad','slug','basilisk','newt','gopher','ferret','seahorse','tuna','buzzard','catfish','rook','felidae','llama','galliform','quokka','koala','asp','bat','viper','horse','guineafowl','marten','bug','turtle','donkey','wasp','damselfly','vicuna','puma','gecko','dove','loon','lemur','panda','marsupial','newt','nightingale','cattle','unicorn','quail','bug','booby','hare','macaw','squirrel','chinchilla','chameleon','clownfish','flamingo','mole','owl','coral','guppy','tarantula','limpet','llama','vicuna','primate','orangutan','reindeer','cat','fox','finch','snail','horse','moose','fox','snail','donkey','sailfish','shark','kangaroo','reindeer','koi','lobster','dog','nightingale','goat','quokka','porcupine','partridge','ladybug','swift','bee','turtle','cricket','duck','marlin','canidae','termite','swan','gopher','eagle','loon','raven','mackerel','louse','peafowl','octopus','penguin','pony','angelfish','partridge','alpaca','cat','pelican','skunk','parrotfish','leech','pigeon','chickadee','mite','blackbird','cow','sparrow','crayfish','centipede','antelope','elk','jay','hedgehog','rat','lion','lobster','alpaca','monkey','hippopotamus','ox','mammal','viper','barracuda','elk','goose','whitefish','peacock','dingo','urial','shrimp','nightingale','armadillo','sole','vicuna','hookworm','otter','hyena','tortoise','wildebeest','gerbil','koi','pheasant','rattlesnake','turtle','pike','asp','cattle','donkey','scorpion','pig','tarsier','tuna','krill','mosquito','anteater','albatross','gerbil','tiglon','pig','lynx','reptile','marlin','cod','parrot','chipmunk','krill','bug','bobolink','cow','toucan','echidna','pinniped','prawn','leopon','catfish','earwig','roadrunner','yak','horse','baboon','fox','toad','yak','cougar','beetle','mule','bug','tyrannosaurus','thrush','mastodon','hoverfly','manatee','platypus','parakeet','zebra','koi','mockingbird','goldfish','crocodile','mosquito','wallaby','penguin','cattle','dingo','monkey','guan','mollusk','pheasant','guineafowl','zebra','lemur','rat','leech','firefly','rodent','condor','slug','goat','goldfish','marmoset','mink','dragon','pinniped','cephalopod','whitefish','chinchilla','rook','salmon','llama','capybara','mastodon','rattlesnake','tarantula','gayal','guppy','tuna','quelea','swallow','anaconda','mongoose','pigeon','pony','damselfly','caterpillar','squid','flea','otter','mockingbird','gazelle','limpet','moose','nightingale','donkey','magpie','penguin','halibut','dolphin','magpie','wolf','coral','koi','lemur','finch','amphibian','earthworm','cricket','goldfish','swallow','tern','bass','ape','raccoon','vicuna','haddock','dragon','barracuda','mackerel','gibbon','bass','beaver','bedbug','ferret','tick','leopard','albatross','orca','bee','bass','cardinal','bird','lizard','iguana','haddock','mink','ferret','vicuna','mouse','penguin','snake','elk','jellyfish','perch','dog','whitefish','lemur','dog','jaguar','pinniped','wolf','salamander','snake','dinosaur','aphid','dingo','narwhal','sheep','galliform','weasel','tiglon','rabbit','limpet','aardvark','sailfish','snail','silverfish','gopher','swordfish','starfish','bobcat','gecko','badger','wildfowl','beetle','bat','sparrow','sturgeon','sole','guanaco','iguana','hornet','sailfish','bear','bedbug','shark','mouse','hamster','parrot','chimpanzee','hookworm','crawdad','mandrill','cougar','mongoose','sturgeon','wasp','hare','iguana','alpaca','hoverfly','wildfowl','fowl','piranha','eel','smelt','wombat','cougar','gull','aardvark','sheep','hookworm','slug','snake','llama','aardvark','beetle','badger','tyrannosaurus','ape','wallaby','dormouse','whitefish','gayal','loon','otter','swordfish','guppy','rook','dinosaur','lynx','flea','opossum','tortoise','pig','grasshopper','angelfish','snake','dingo','lion','takin','baboon','coyote','earwig','booby','whippet','llama','halibut','alligator','tortoise','beetle','goat','mink','tuna','pheasant','krill','mouse','blackbird','trout','squid','bedbug','quelea','tyrannosaurus','mollusk','puma','mammal','dinosaur','platypus','opossum','mule','emu','cobra','salamander','spider','lungfish','wolf','ant','gibbon','owl','gibbon','yak','quelea','warbler','roundworm','gerbil','guineafowl','giraffe','pigeon','wallaby','fish','damselfly','capybara','beetle','chinchilla','roadrunner','turkey','bug','anaconda','chicken','guppy','caribou','chickadee','zebra','reindeer','carp','smelt','sturgeon','gopher','bird','leopard','krill','hornet','lungfish','wren','snipe','walrus','woodpecker','cattle','cat','cattle','xerinae','tuna','boar','chicken','leopon','ox','impala','felidae','possum','boar','cockroach','hornet','koi','impala','skunk','viper','cheetah','crawdad','reptile','gamefowl','piranha','hoverfly','quail','koi','mosquito','guppy','silverfish','tarantula','rooster','lynx','spider','walrus','cicada','anglerfish','salmon','salmon','raven','whitefish','weasel','ocelot','elk','rabbit','mammal','gibbon','guan','lion','guppy','constrictor','harrier','badger','jellyfish','guppy','reptile','jaguar','panther','gerbil','chinchilla','parrot','asp','hoverfly','flea','koi','bovid','eagle','urial','flea','goldfish','albatross','alpaca','amphibian','bandicoot','cattle','warbler','coral','penguin','gerbil','tarantula','alpaca','swan','hummingbird','butterfly','chicken','camel','moth','catfish','urial','clam','butterfly','tern','crow','flea','yak','louse','jellyfish','damselfly','turtle','bobolink','toad','vole','macaw','kite','finch','walrus','loon','hornet','roadrunner','swan','skink','hippopotamus','wren','chicken','ostrich','opossum','turtle','rabbit','goat','lamprey','krill','snake','camel','antelope','porcupine','ferret','gayal','wombat','llama','cricket','possum',
    'viper','badger','beetle','earthworm','hamster','bonobo','anteater','impala','bug','takin','crawdad','hummingbird','kangaroo','deer','zebra','crow','butterfly','aardvark','narwhal','guppy','mackerel','guppy','bison','buzzard','ocelot','hyena','partridge','scallop','bobolink','lynx','gopher','ostrich','silverfish','barracuda','wildcat','pheasant','tiglon','cardinal','wallaby','quail','bonobo','duck','pinniped','vicuna','firefly','pike','elk','dog','raccoon','perch','hamster','constrictor','planarian','pigeon','scorpion','fish','panda','cod','squid','catfish','mosquito','otter','emu','reindeer','walrus','cow','smelt','goose','woodpecker','leopard','gecko','pelican','rattlesnake','weasel','aardvark','anglerfish','finch','crow','piranha','newt','iguana','galliform','leopon','dog','tiger','stingray','wildfowl','hookworm','anteater','boa','partridge','lemming','opossum','wallaby','puffin','cow','heron','quelea','ostrich','kingfisher','krill','guppy','thrush','reindeer','scorpion','orangutan','constrictor','badger','krill','fly','manatee','owl','macaw','anteater','fox','lungfish','harrier','hawk','marmot','bird','mollusk','canidae','leopon','starfish','rhinoceros','salmon','guan','bee','ocelot','hoverfly','rattlesnake','silverfish','swan','pheasant','guppy','dove','marmot','planarian','parrot','pig','rooster','koi','dinosaur','cow','elephant','nightingale','raccoon','dinosaur','guppy','warbler','chickadee','egret','buzzard','macaw','camel','bee','dingo','felidae','crawdad','donkey','quokka','meerkat','ermine','koi','puffin','spider','macaw','planarian','dog','hyena','ostrich','leopard','tarsier','cockroach','octopus','echidna','partridge','bear','anteater','llama','guineafowl','sturgeon','rhinoceros','urial','snipe','dragon','anteater','harrier','wren','guineafowl','llama','lamprey','porpoise','anglerfish','clam','herring','damselfly','whippet','tuna','barracuda','earwig','cod','bass','hookworm','swordfish','coyote','boar','ferret','ant','marsupial','peafowl','armadillo','swordtail','iguana','marmoset','ant','wasp','goat','termite','antelope','marsupial','alpaca','viper','grouse','mongoose','lamprey','lion','tuna','rabbit','booby','sloth','shark','hedgehog','aphid','puma','crab','parrot','vulture','porpoise','manatee','marsupial','hippopotamus','porpoise','urial','takin','hare','beaver','grouse','egret','cephalopod','llama','heron','mammal','mouse','mockingbird','bat','muskox','horse','silverfish','ladybug','dove','minnow','donkey','turkey','sheep','anaconda','mollusk','whitefish','hippopotamus','pelican','mastodon','hawk','damselfly','tern','skink','ptarmigan','gibbon','moth','coyote','flea','hippopotamus','camel','leech','shrew','louse','finch','earwig','salamander','goldfish','cricket','turkey','lamprey','jay','snail','mule','raven','swallow','raccoon','cockroach','macaw','crawdad','leech','goose','tarsier','caribou','donkey','crab','tapir','flamingo','takin','firefly','grouse','parrot','cattle','parrot','buzzard','tick','mongoose','meerkat','cow','clownfish','galliform','bison','impala','hippopotamus','gull','penguin','donkey','hummingbird','sheep','wasp','cheetah','vole','otter','kingfisher','porpoise','possum','swan','hornet','roundworm','kite','alpaca','manatee','gibbon','cougar','canidae','junglefowl','salmon','hawk','snail','pheasant','sturgeon','kite','parrot','rook','sole','mongoose','walrus','macaw','flyingfish','cephalopod','mastodon','tuna','caribou','trout','mongoose','grasshopper','silkworm','manatee','swift','tick','basilisk','marten','viper','ostrich','mackerel','damselfly','chipmunk','marlin','cattle','elephant','vulture','kangaroo','clownfish','caribou','ant','llama','caribou','mite','swift','cricket','canid','mammal','crow','slug','sheep','wolverine','crawdad','earthworm','aardvark','puffin','egret','crane','amphibian','rabbit','xerinae','wolf','antelope','cougar','jay','caterpillar','eel','earwig','booby','sheep','ape','badger','wolf','lemming','quelea','mosquito','reindeer','swift','wildfowl','goat','marsupial','narwhal','pigeon','marlin','muskox','aphid','dinosaur','python','tapir','bass','lion','swallow','jackal','reptile','lynx','donkey','mackerel','canidae','basilisk','damselfly','meerkat','mandrill','shrimp','leopon','gorilla','pinniped','perch','hookworm','impala','asp','weasel','mouse','walrus','lynx','hippopotamus','camel','tahr','orangutan','takin','hare','wildebeest','lion','marmoset','baboon','zebra','duck','boar','dog','kangaroo','lungfish','koi','mockingbird','cricket','canid','ant','barnacle','takin','worm','bug','gopher','hamster','dinosaur','bear','eagle','aphid','camel','earthworm','mosquito','barracuda','ladybug','toad','rook','monkey','bobolink','carp')

    #importing time and user input to perform word selection
    $time = [int](Get-Date -UFormat %s -Millisecond 0)
    $userInput = Read-Host "enter a 3 digit number: "

    #do some math to decide which words
    
    $seed = $time/1000000*$userInput

    $getWord1 = Get-Random -Minimum 0 -Maximum 1299 -SetSeed ($seed*.2534)
    $getWord2 = Get-Random -Minimum 0 -Maximum 1299 -SetSeed ($seed*.4509)
    $getWord3 = Get-Random -Minimum 0 -Maximum 1299 -SetSeed ($seed*.0946)

    $word1 = $wordList[$getWord1]
    $word2 = $wordList[$getWord2]
    $word3 = $wordList[$getWord3]

    #use time to create the end number

    $endNum = [int](($time/$userInput/537)*.05768)

    #use user input to select special character delimiter for words
    #actually just gonna use underscore for now till i know which special characters mess up command lines

    $delimiter = '_'

    #make an alert so user can record the special numbers

    $wshell = New-Object -ComObject Wscript.Shell
    $alert = $wshell.Popup("Time: " + $time + " Input: " + $userInput,0,"RECORD THE FOLLOWING:",0+48)

    #concatonate everything together and return

    $temp = $word1 + $delimiter + $word2 + $delimiter + $word3 + $endNum + "!"

    return $temp

}