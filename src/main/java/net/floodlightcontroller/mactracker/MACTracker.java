package net.floodlightcontroller.mactracker;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;

import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActions;

import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructions;


import net.floodlightcontroller.packet.Ethernet;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.MacAddress;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;


import net.floodlightcontroller.core.IFloodlightProviderService;

import java.util.concurrent.ConcurrentSkipListSet;

import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
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
			installDropRule(sw, eth.getSourceMACAddress().toString());
		
        } else if (!originalMac.equals(eth.getSourceMACAddress())) {
            // La MAC es diferente de la original, podría ser un intento de spoofing
            logger.warn("MAC Spoofing Detected: {} on switch: {}",
                    eth.getSourceMACAddress().toString(),
                    sw.getId().toString());
            
			 // Mitigación: Instalar regla para dropear paquetes con la MAC falsa
			installDropRule(sw, eth.getSourceMACAddress().toString());
        }

        return Command.CONTINUE;
    }




    private static final String CONTROLLER_IP = "127.0.0.1";
    private static final int CONTROLLER_PORT = 8080;
	// Método para instalar una regla en el switch para dropear paquetes con una MAC específica
	private void installDropRule(IOFSwitch sw, String spoofedMac) {
        /*OFFactory myFactory = sw.getOFFactory();

        Match match = myFactory.buildMatch()
                .setExact(MatchField.ETH_SRC, spoofedMac)
                .build();

        OFAction dropAction = myFactory.actions().output(OFPort.ANY, Integer.MAX_VALUE);
        List<OFAction> actions = Collections.singletonList(dropAction);
        OFInstruction dropInstruction = myFactory.instructions().applyActions(actions);

        sw.write(myFactory.buildFlowAdd()
                .setBufferId(OFBufferId.NO_BUFFER)
                .setPriority(1000)
                .setIdleTimeout(60)
                .setMatch(match)
                .setInstructions(Collections.singletonList(dropInstruction))
                .setTableId(TableId.ALL)
                .build());

        logger.info("Drop rule installed on switch: {} for SPOOFED MAC: {}",
                sw.getId().toString(),
                spoofedMac.toString());*/

        String flowName = "drop-rule-mac-spoofing";
        String switchDpid = sw.getId().toString();
        try {
            String apiUrl = String.format("http://%s:%d/wm/staticflowpusher/json", CONTROLLER_IP, CONTROLLER_PORT);
            String requestBody = String.format("{\"switch\": \"%s\", \"name\": \"%s\", \"eth_src\": \"%s\", \"actions\": \"drop\", \"idle_timeout\": %d}", switchDpid, flowName, spoofedMac, 60);


            URL url = new URL(apiUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = requestBody.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                System.out.println("Flow entry added successfully.");
                logger.info("Drop rule installed on switch: {} for SPOOFED MAC: {}",
                        sw.getId().toString(),
                        spoofedMac);
            } else {
                System.err.println("Error adding flow entry. Response code: " + responseCode);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

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