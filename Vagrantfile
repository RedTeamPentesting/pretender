Vagrant.configure("2") do |config|
  config.vm.define :deb do |deb|
    deb.vm.box = "redteam/debian10"
    deb.vm.network :private_network, ip: "10.0.0.10", virtualbox__intnet: "pretender"
    deb.vm.hostname = "deb"
  end

  config.vm.define :win do |win|
    win.vm.box = "redteam/win10"
    win.vm.network :private_network, ip: "10.0.0.11", virtualbox__intnet: "pretender"
    win.vm.hostname = "win"
  end

  config.vm.define :win2 do |win2|
    win2.vm.box = "redteam/win10"
    win2.vm.network :private_network, ip: "10.0.0.12", virtualbox__intnet: "pretender"
    win2.vm.hostname = "win2"
  end
end
