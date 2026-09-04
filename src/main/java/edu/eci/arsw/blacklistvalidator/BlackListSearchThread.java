package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class BlackListSearchThread extends Thread {

    private final String ipaddress;
    private final int startIndex;
    private final int endIndex;
    private final int alarmCount;
    private final AtomicInteger occurrencesCount;
    private final AtomicBoolean targetReached;
    private final List<Integer> blackListOcurrences;

    public BlackListSearchThread(String ipaddress, int startIndex, int endIndex, int alarmCount,
            AtomicInteger occurrencesCount, AtomicBoolean targetReached, List<Integer> blackListOcurrences) {
        this.ipaddress = ipaddress;
        this.startIndex = startIndex;
        this.endIndex = endIndex;
        this.alarmCount = alarmCount;
        this.occurrencesCount = occurrencesCount;
        this.targetReached = targetReached;
        this.blackListOcurrences = blackListOcurrences;
    }

    @Override
    public void run() {
        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();

        for (int i = startIndex; i < endIndex && !targetReached.get(); i++) {
            if (skds.isInBlackListServer(i, ipaddress)) {
                blackListOcurrences.add(i);
                if (occurrencesCount.incrementAndGet() >= alarmCount) {
                    targetReached.set(true);
                }
            }
        }
    }
}
