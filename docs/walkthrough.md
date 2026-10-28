# A case to explain at the whiteboard

The fictional university team has capacity for only a few fixes this week. The archive test service carries severity 10, while the portal component carries 8.1. Ask what the severity number leaves out before looking at the score.

The portal is exposed to the internet, marked important, and flagged as known exploited in the sample. Its default score is `48.6 + 12 + 24 + 20 = 104.6`. The isolated test asset scores `60 + 0 + 0 + 0 = 60`. This explains the rank reversal. It does not establish how likely either asset is to be compromised.

Try removing the exposure weight. The top five now include the payment worker instead of the library search service. Explain which organizational assumption changed. Then double the exploitation weight: some numerical scores change while the top-five membership stays the same. Stable membership under one intervention is not general robustness.

For the lifecycle exercise, mark the portal resolved and import scan 02. A new scanner observation reopens it. Investigate whether the fix failed, the scanner is stale, or the identifier matches a different instance. The application does not settle those questions.

Finally, inspect the library service: scan 02 marks it no longer exposed. Its score falls, but the finding still exists. Verify the network change before treating the reduced priority as justified.

## Notes for your own experiment

Record the date you ran the tool, the input change, your expectation, the observed ordering, and one alternative explanation. Keep your own wording and observations. There are no prewritten personal reflections or invented analyst interviews in this project.
