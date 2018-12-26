# Copyright (C) 2015 Johnny Vestergaard <jkv@unixcluster.dk>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

#import json
import logging
import re
import subprocess

from sqlalchemy import Table, Column, Integer, String, MetaData, TEXT, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exc
import glastopf.modules.processing.ip_profile as ipp

logger = logging.getLogger(__name__)


class Database(object):
    def __init__(self, engine):
        self.engine = engine
        ipp.Base.metadata.create_all(self.engine)
        self.setup_mapping()
        self.session = sessionmaker(bind=self.engine)()

    def createASN(self, conn, peerIP):
        def addslashes(s):
            l = ["\\", '"', "'", "\0", ]
            for i in l:
                if i in s:
                    s = s.replace(i, '\\'+i)
            return s

        def reverseIP(address):
            temp = re.split("\.", address)
            convertedAddress = str(temp[3]) +'.' + str(temp[2]) + '.' + str(temp[1]) +'.' + str(temp[0])
            return convertedAddress

        querycmd1 = reverseIP(peerIP) + '.origin.asn.cymru.com'
        response1 = subprocess.Popen(['dig', '-t', 'TXT', querycmd1, '+short'], stdout=subprocess.PIPE).communicate()[0].decode('utf-8')
        response1List = re.split('\|', response1)
        ASN = response1List[0].strip('" ')
        querycmd2 = 'AS' + ASN + '.asn.cymru.com'
        response2 = subprocess.Popen(['dig', '-t', 'TXT', querycmd2, '+short'], stdout=subprocess.PIPE).communicate()[0].decode('utf-8')
        response2List = re.split('\|', response2)
        if len(response2List) < 4:
            asnid = 1
        else:
            isp = addslashes(response2List[4].replace('"', '').strip('"\' \n'))
            network = addslashes(response1List[1].strip('"\' \n'))
            country = addslashes(response1List[2].strip('"\' \n'))
            registry = addslashes(response1List[3].strip('"\' \n'))
            isp = network + "-" + isp
            res = conn.execute("""SELECT `asnid` FROM `asinfo` WHERE `asn` = %s AND `rir` = %s AND `country` = %s AND `asname` = %s """, (ASN, registry, country, isp))
            r = res.fetchone()
            res.close()
            if r:
                asnid = int(r[0])
                logger.info("Existing AS response (%s,%s,%s,%s), asnid = %i" % (isp, network, country, registry, asnid))
            else:
                res = conn.execute("""INSERT INTO `asinfo` (`asn`, `rir`, `country`, `asname`) VALUES (%s, %s, %s, %s) """, (ASN, registry, country, isp))
                asnid = res.lastrowid
                res.close()
                logger.info("New AS response (%s,%s,%s,%s), asnid = %i" % (isp, network, country, registry, asnid))
      
        return asnid

    def insert(self, attack_event):
        try:
            conn = self.engine.connect()
            entry = attack_event.event_dict()
            entry['asnid'] = self.createASN(conn, entry['source'][0])
            entry['source'] = (entry['source'][0] + ":" + str(entry['source'][1]))
            conn.execute(self.events_table.insert(entry))
        except exc.OperationalError as e:
            logger.error("Error inserting attack event into main database: {0}".format(e))

    def insert_profile(self, ip_profile):
        # print "last_event_time for ip %s:%s"%(
        #             ip_profile.ip, ip_profile.last_event_time)
        # .split()[0] is added to deal with multiple ASNs
        self.session.add(ip_profile)
        try:
            self.session.commit()
        except exc.OperationalError as e:
            self.session.rollback()
            logger.error("Error inserting profile into main database: {0}".format(e))

    def update_db(self):
        try:
            self.session.commit()
        except exc.OperationalError as e:
            self.session.rollback()
            logger.error("Error updating profile in main database: {0}".format(e))

    def get_profile(self, source_ip):
        ip_profile = self.session.query(ipp.IPProfile).filter(
            ipp.IPProfile.ip == source_ip).first()
        return ip_profile

    def setup_mapping(self):
        meta = MetaData()
        self.events_table = Table(
            'events', meta,
            Column('id', Integer, primary_key=True, ),
            Column('time', String(30)),
            Column('source', String(30)),
            Column('request_url', String(500)),
            Column('request_raw', TEXT),
            Column('pattern', String(20)),
            Column('filename', String(500)),
            Column('file_sha256', String(500)),
            Column('version', String(10)),
            Column('sensorid', String(36)),
            Column('known_file', Boolean())
            Column('asnid', Integer)
        )
        #only creates if it cant find the schema
        meta.create_all(self.engine)
