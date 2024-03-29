import psycopg2 as ag
import requests, json, sys
from multicorn import ForeignDataWrapper
from multicorn.utils import log_to_postgres
from stix2 import TAXIICollectionSource,Filter
from stix2.utils import get_type_from_id
from taxii2client import Collection


class MitreTaxiiForeignDataWrapper(ForeignDataWrapper):
   def get_intrusion_set(self,src):
      return src.query([
          Filter('type','=','intrusion-set')
      ])

   def __init__(self, options, columns):
      super(MitreTaxiiForeignDataWrapper, self).__init__(options,columns)
      self.columns = columns

   def execute(self, quals, columns):
      collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")
      tc_source = TAXIICollectionSource(collection)
      
      group = self.get_intrusion_set(tc_source)
      for index in range(0,len(group)):
         intrusion_set = dict(group[index])
         line = {}
         for column_name in self.columns:
            if (column_name == 'external_references'):
               ext_ref = intrusion_set[column_name]
               ref_list = list()
               for index in range(0,len(ext_ref)):                
                  if('url' in ext_ref[index]):
                     ref_list.append(ext_ref[index]['url'])
               line[column_name] = ref_list
            elif (column_name == 'aliases'):
               if ('aliases' in intrusion_set):
                  line[column_name] = intrusion_set[column_name]
            elif (column_name == 'description'):
               if ('description' in intrusion_set):
                  line[column_name] = intrusion_set[column_name].replace('\n','').strip()
            else: 
               line[column_name] = intrusion_set[column_name]
         yield line

class MitreAttackPatternForeignDataWrapper(ForeignDataWrapper):
   def get_attack_pattern(self,src,stix_id):
      relations = src.relationships(stix_id,'uses',source_only=True)
      return src.query([
          Filter('type','=','attack-pattern'),
          Filter('id','in',[r.target_ref for r in relations])
      ])

   def __init__(self,options,columns):
      super(MitreAttackPatternForeignDataWrapper,self).__init__(options,columns)
      self.columns = columns

   def execute(self, quals, columns):
      collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")
      tc_source = TAXIICollectionSource(collection)
         
      conn_string = "host=127.0.0.1 port=5555 dbname=ctias user=ctias password=citas"
      query = "SELECT id,name FROM mitre_intrusion_set"

      try:
         conn = ag.connect(conn_string)
         cur = conn.cursor()
    
         cur.execute(query)
         while True:
            records = cur.fetchall()
            if not records:
               break
  
            for i in range(0,len(records)):
               line = dict()
               intrusion_set_id = records[i][0]
               intrusion_set_name = records[i][1]
               result = self.get_attack_pattern(tc_source,intrusion_set_id)
               for j in range(0,len(result)):
                  tmp_attack_pattern=dict(result[j])
                  for column_name in self.columns:
                     if (column_name == 'external_references'):
                        ext_ref = tmp_attack_pattern[column_name]
                        ref_list = list()
                        for index in range(0,len(ext_ref)):
                           if('url' in ext_ref[index]):
                              ref_list.append(ext_ref[index]['url'])
                        line[column_name] = ref_list
                     elif (column_name == 'kill_chain_phases'):
                        kc_phase = tmp_attack_pattern[column_name]
                        line[column_name] = kc_phase[0]['phase_name']
                     elif (column_name == 'platforms'):
                        if ('x_mitre_platforms' in tmp_attack_pattern):
                           line[column_name] = tmp_attack_pattern['x_mitre_platforms']
                     elif (column_name == 'id'):
                        if ('id' in tmp_attack_pattern):
                           line[column_name] = tmp_attack_pattern[column_name]
                     elif (column_name == 'name'):
                        if ('name' in tmp_attack_pattern):
                           line[column_name] = tmp_attack_pattern[column_name]
                     elif (column_name == 'gid'):
                        line[column_name] = intrusion_set_id
                     elif (column_name == 'gname'):
                        line[column_name] = intrusion_set_name
                     else:
                        line[column_name] = tmp_attack_pattern[column_name]

                  yield line
      except Exception, e:
         log_to_postgres(e)
      finally:
         cur.close()
         conn.close()

class ThreatMinerForeignDataWrapper(ForeignDataWrapper):
   def __init__(self, options, columns):
      super(ThreatMinerForeignDataWrapper, self).__init__(options,columns)
      self.columns = columns

   def execute(self, quals, columns):
      intrusion_set_list = []
      conn_string = "host=127.0.0.1 port=5555 dbname=ctias user=ctias password=citas"
      query = "SELECT id,name FROM mitre_intrusion_set"
      reports_api = "https://api.threatminer.org/v2/reports.php"      
      report_api = "https://api.threatminer.org/v2/report.php"
      try:
         conn = ag.connect(conn_string)
         cur = conn.cursor()
        
         cur.execute(query)
         while True:
            records = cur.fetchall()
            if not records:
               break
            
            for i in range(0,len(records)):
               line = dict()
               intrusion_set_id = records[i][0]
               intrusion_set_name = records[i][1]
               reports = json.loads(requests.get(reports_api,{"q":intrusion_set_name,"rt":1}).text)
               if (reports['status_code'] == '200'):
                  for j in range(0,len(reports['results'])):
                     reports_result = reports['results'][j]
                     file_name = reports_result['filename']
                     domain_result = json.loads(requests.get(report_api,{"q":file_name, \
                                  "y":reports_result['year'],"rt":1}).text)
                     ip_result = json.loads(requests.get(report_api,{"q":file_name, \
                                "y":reports_result['year'], "rt":2}).text)
                     email_result = json.loads(requests.get(report_api,{"q":file_name, \
                                 "y":reports_result['year'], "rt":3}).text)
                     hash_result = json.loads(requests.get(report_api,{"q":file_name, \
                               "y":reports_result['year'],"rt":4}).text)

                     for column_name in self.columns:
                        if (column_name == 'id'):
                           line[column_name] = intrusion_set_id
                        elif (column_name == 'name'):
                           line[column_name] = intrusion_set_name
                        elif (column_name == 'filename'):
                           line[column_name] = file_name
                        elif (column_name == 'domain_list'):
                           line[column_name] = domain_result['results']
                        elif (column_name == 'ip_list'):
                           line[column_name] = ip_result['results']
                        elif (column_name == 'email_list'):
                           line[column_name] = email_result['results']
                        elif (column_name == 'hash_list'):
                           line[column_name] = hash_result['results']

                     yield line
      except Exception, e:
         log_to_postgres(e)
      finally:
         cur.close()
         conn.close()

class ThreatCrowdForeignDataWrapper(ForeignDataWrapper):
   def __init__(self, options, columns):
      super(ThreatCrowdForeignDataWrapper, self).__init__(options,columns)
      self.columns = columns

   def execute(self, quals, columns):
      intrusion_set_list = []
      conn_string = "host=127.0.0.1 port=5555 dbname=ctias user=ctias password=citas"
      query = "SELECT unnest(hash_list) FROM threat_miner_indicator"
      report_api = "http://www.threatcrowd.org/searchApi/v2/file/report"      
      try:
         conn = ag.connect(conn_string)
         cur = conn.cursor()
        
         cur.execute(query)
         while True:
            records = cur.fetchall()
            if not records:
               break
            
            for i in range(0,len(records)):
               line = dict()
               #intrusion_set_id = records[i][0]
               #intrusion_set_name = records[i][1]
               indicator_hash = records[i][0]
               reports = json.loads(requests.get(report_api,{"resource":indicator_hash}).text)
               if (reports['response_code'] == '1'):
                  for column_name in self.columns:
                     if (column_name == 'md5'):
                        line[column_name] = reports[column_name]
                     elif (column_name == 'sha1'):
                        line[column_name] = reports[column_name]
                     elif (column_name == 'filename'):
                        line[column_name] = reports['scans']
                     elif (column_name == 'exploit_ip'):
                        line[column_name] = reports['ips']
                     elif (column_name == 'exploit_domain'):
                        line[column_name] = reports['domains']

                  yield line
      except Exception, e:
         log_to_postgres(e)
      finally:
         cur.close()
         conn.close()
