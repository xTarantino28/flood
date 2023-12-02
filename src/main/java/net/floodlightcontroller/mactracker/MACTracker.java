package net.floodlightcontroller.mactracker;
import java.util.Collection;
import java.util.Map;

import net.floodlightcontroller.packet.Ethernet;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.MacAddress;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;


import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public class MACTracker implements IOFMessageListener, IFloodlightModule  {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;

    @Override
    public String getName() {
        return MACTracker.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context)
            throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(MACTracker.class);
		// Agregar MACs originales hardcoded al HashMap en el método init
        addOriginalMac(MacAddress.of("fa:16:3e:5c:73:86")); //cliente1 ubuntu
        addOriginalMac(MacAddress.of("fa:16:3e:6c:ff:86")); //cliente2 ubuntu
		addOriginalMac(MacAddress.of("fa:16:3e:39:16:d8")); //cliente3 kali

    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

    }
	
	
	// Almacena las MAC originales de los dispositivos en la red
    private Map<Long, MacAddress> originalMacs = new HashMap<>();
	

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        Ethernet eth =
                IFloodlightProviderService.bcStore.get(cntx,
                        IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		/* ORIGINAL MACTRACKER CODE
        Long sourceMACHash = eth.getSourceMACAddress().getLong();
        if (!macAddresses.contains(sourceMACHash)) {
            macAddresses.add(sourceMACHash);
            logger.info("MAC Address: {} seen on switch: {}",
                    eth.getSourceMACAddress().toString(),
                    sw.getId().toString());
        }
        return Command.CONTINUE;*/
		
		
		//MAC SPOOFING DETECTION
		Long sourceMACHash = eth.getSourceMACAddress().getLong();
        MacAddress originalMac = originalMacs.get(sourceMACHash);

        if (originalMac == null) {
            // La MAC no está en la base de datos, podría ser un intento de spoofing
            logger.warn("Possible MAC Spoofing: {} on switch: {}",
                    eth.getSourceMACAddress().toString(),
                    sw.getId().toString());
            
			// Mitigación: Instalar regla para dropear paquetes con la MAC falsa
			installDropRule(sw, eth.getSourceMACAddress());
		
        } else if (!originalMac.equals(eth.getSourceMACAddress())) {
            // La MAC es diferente de la original, podría ser un intento de spoofing
            logger.warn("MAC Spoofing Detected: {} on switch: {}",
                    eth.getSourceMACAddress().toString(),
                    sw.getId().toString());
            
			 // Mitigación: Instalar regla para dropear paquetes con la MAC falsa
			installDropRule(sw, eth.getSourceMACAddress());
        }

        return Command.CONTINUE;
    }
	
	
	// Método para instalar una regla en el switch para dropear paquetes con una MAC específica
	private void installDropRule(IOFSwitch sw, MacAddress spoofedMac) {
		OFFactory myFactory = sw.getOFFactory();
		Match match = myFactory.buildMatch()
				.setExact(MatchField.ETH_SRC, spoofedMac)
				.build();

		OFOxmWildcard wildcard = myFactory.oxms().ethSrcMasked(spoofedMac, MacAddress.NO_MASK);

		OFAction dropAction = myFactory.actions().drop();

		OFInstruction dropInstruction = myFactory.instructions().applyActions(
				myFactory.instructions().buildActions().setActions(dropAction));

		OFFlowTable flowTable = myFactory.buildFlowTable()
				.setTableId(TableId.ALL)
				.build();

		sw.write(myFactory.buildFlowAdd()
				.setBufferId(OFBufferId.NO_BUFFER)
				.setPriority(1000)
				.setIdleTimeout(60)
				.setMatch(match)
				.setInstructions(myFactory.instructions().applyActions(OFActions.empty()))
				.setTableId(TableId.ALL)
				.build());

		logger.info("Drop rule installed on switch: {} for SPOOFED MAC: {}",
				sw.getId().toString(),
				spoofedMac.toString());
	}
	
	
	
	
	
	
	// Método para agregar MACs originales a la base de datos
    public void addOriginalMac(MacAddress originalMac) {
        Long macHash = originalMac.getLong();
        originalMacs.put(macHash, originalMac);
    }

    // Método para eliminar MACs originales de la base de datos (puedes usarlo si es necesario)
    public void removeOriginalMac(MacAddress originalMac) {
        Long macHash = originalMac.getLong();
        originalMacs.remove(macHash);
    }





}