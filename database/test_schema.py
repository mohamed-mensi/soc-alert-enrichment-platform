from database.db_manager import DBManager
db = DBManager()
print('Total IOCs:', db.get_ioc_count())
print('Feodo:', db.get_ioc_count('abusech_feodo'))
print('URLhaus:', db.get_ioc_count('abusech_urlhaus'))
print('ThreatFox:', db.get_ioc_count('abusech_threatfox'))
print('OTX:', db.get_ioc_count('otx'))
