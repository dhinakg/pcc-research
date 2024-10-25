# pcc-research

Assorted PCC research

## Releases

1. Make a `proto` folder. Copy the following files from the PCC repository:
   - `./srd_tools/vre/pccvre/TransparencyLog/Proto/ATServiceApi.proto`
   - `./srd_tools/vre/pccvre/TransparencyLog/Proto/AuditorApi.proto`
   - `./srd_tools/vre/pccvre/TransparencyLog/Proto/Transparency.proto`
   - `./srd_tools/vre/pccvre/TransparencyLog/Proto/ATResearcherApi.proto`
   - `./srd_tools/vre/pccvre/TransparencyLog/Proto/KtClientApi.proto`
   - `./srd_tools/vre/pccvre/SWReleases/Proto/ReleaseMetadata.proto`
2. Set up venv (or use Poetry, if you have it installed)
   1. `python3 -m venv .env`
   2. `source .env/bin/activate`
   3. `pip install -r requirements.txt`
3. Compile the protos
   1. `mkdir lib`
   2. `cd proto`
   3. `protoc -I . --python_betterproto_out=../lib *.proto`
4. `python3 protohell.py`
5. Look at the `releases` folder
