/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT=5;
    
    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    // Punto 1: búsqueda por segmentos delegada a BlackListSearchThread. Punto 2: N hilos, repartiendo el rango de servidores entre ellos (contemplando residuo si N no divide exacto al total).
    public List<Integer> checkHost(String ipaddress, int N){

        List<Integer> blackListOcurrences=new CopyOnWriteArrayList<>();

        AtomicInteger ocurrencesCount=new AtomicInteger(0);

        AtomicBoolean targetReached=new AtomicBoolean(false);

        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();

        int totalServers=skds.getRegisteredServersCount();

        int baseSize=totalServers/N;
        int remainder=totalServers%N;

        List<BlackListSearchThread> threads=new LinkedList<>();

        int start=0;
        for (int t=0;t<N;t++){
            int size=baseSize+(t<remainder?1:0);
            int end=start+size;

            BlackListSearchThread thread=new BlackListSearchThread(ipaddress, start, end, BLACK_LIST_ALARM_COUNT, ocurrencesCount, targetReached, blackListOcurrences);
            threads.add(thread);
            thread.start();

            start=end;
        }

        for (BlackListSearchThread thread:threads){
            try {
                thread.join();
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }

        if (ocurrencesCount.get()>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists with {0} threads, occurrences found:{1}", new Object[]{N, ocurrencesCount.get()});

        return blackListOcurrences;
    }
    
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    
    
    
}
