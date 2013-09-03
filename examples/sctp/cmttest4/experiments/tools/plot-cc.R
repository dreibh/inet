# ###########################################################################
# Name:        plot-cc.R
# Description: Plot Congestion Window variables from vector file
# Revision:    $Id: plot-cc.R 1050 2012-09-25 20:07:51Z dreibh $
# ###########################################################################

# ###### Get useful tick range for congestion window values #################
getUsefulWindowRange <- function(timeSet, valueSet)
{
   duration <- max(timeSet) - min(timeSet)
   start    <- min(timeSet) + 0.3 * duration   # Ignore first 30%
   stop     <- max(timeSet) - 0.1 * duration   # Ignore last 10%
   set <- subset(valueSet, ((timeSet >= start) & (timeSet <= stop) & (valueSet < 1000000000)))
   if(length(set) < 1) {
      set <- subset(valueSet, (valueSet <= 100000))
   }

   range <- getUsefulTicks(set)
   return(range)
}

# ###### Get useful x-axis ticks for flow runtime ###########################
getUsefulTimeRange <- function(timeSet)
{
   a <- floor(min(timeSet))
   b <- ceiling(max(timeSet))
   range <- seq(a, b, 1)

   # ------ Time Range ----------------
#    range <- seq(1, 5, 0.2)
   # ----------------------------------

   # range <- seq(a, b, (b - a) / 10)
   # range <- getIntegerTicks(timeSet)
   return(range)
}


# ###### Plot Cwnd and SS Threshold #########################################
plotCwndAndSST <- function(data, outputName, yTitle="Window Size [Bytes]")
{
   title  <- outputName
   addBookmarkInPDFMetadata(1, title)

   xSet <- data$Time
   if(length(xSet) < 1) {
      cat(sep="", "NOTE: Skipping ", outputName, ": no data to plot!\n")
      return(FALSE)
   }
   xTitle <- "Time{t}[s]"
   xAxisTicks <- getUsefulTimeRange(xSet)
   # xAxisTicks <- seq(0,5,1)

   ySet <- data$Value
   yAxisTicks <- getUsefulWindowRange(xSet, ySet)
#    yAxisTicks <- seq(0, 100000, 10000)

   zSet <- data$Split  ; zTitle <- "Path{:psi:}"
   vSet <- data$Vector ; vTitle <- "Vector{:nu:}"
   wSet <- c() ; wTitle <- ""
   aSet <- c() ; aTitle <- "" ; bSet <- c() ; bTitle <- ""
   pSet <- data$Object ; pTitle <- "Object{:Omega:}"

   # print(levels(factor(zSet)))
   # print(levels(factor(vSet)))

   zColorArray    <- rainbow2(3)
   dotScaleFactor <- 1.25
   legendPos      <- c(0.5,1)   # Legend position (0,0) to (1,1)

   plotstd6(title,
            pTitle, aTitle, bTitle, xTitle, yTitle, zTitle,
            pSet, aSet, bSet, xSet, ySet, zSet,
            vSet, wSet, vTitle, wTitle,
            xAxisTicks=xAxisTicks,
            yAxisTicks=yAxisTicks,
            dotScaleFactor=dotScaleFactor,
            type="stepsx",
            colorMode=cmColor,
            zColorArray=zColorArray,
            hideLegend=FALSE,
            legendPos=legendPos)
}


# ###### Plot Gap Information ###############################################
plotGapInfo <- function(data, outputName)
{
   title  <- outputName
   addBookmarkInPDFMetadata(1, title)

   xSet <- data$Time
   xTitle <- "Time{t}[s]"
   xAxisTicks <- getUsefulTimeRange(xSet)
   # xAxisTicks <- seq(0,5,1)

   ySet <- data$Value
   yTitle <- paste(sep="", outputName, "[1]")
   yAxisTicks <- getUsefulTicks(ySet)
   # yAxisTicks <- seq(0, 1000, 100)

   zSet <- data$Split  ; zTitle <- "Path{:psi:}"
   vSet <- data$Vector ; vTitle <- "Vector{:nu:}"
   wSet <- c() ; wTitle <- ""
   aSet <- c() ; aTitle <- "" ; bSet <- c() ; bTitle <- ""
   pSet <- data$Object ; pTitle <- "Object{:Omega:}"

   zColorArray    <- rainbow2(3)
   dotScaleFactor <- 1.25
   legendPos      <- c(0.5,1)   # Legend position (0,0) to (1,1)

   plotstd6(title,
            pTitle, aTitle, bTitle, xTitle, yTitle, zTitle,
            pSet, aSet, bSet, xSet, ySet, zSet,
            vSet, wSet, vTitle, wTitle,
            xAxisTicks=xAxisTicks,
            yAxisTicks=yAxisTicks,
            type="stepsx",
            colorMode=cmColor,
            zColorArray=zColorArray,
            hideLegend=FALSE,
            legendPos=legendPos)
}


# ###### Plot RTT and RTO ###################################################
plotRTTorRTO <- function(data, outputName)
{
   title  <- outputName
   addBookmarkInPDFMetadata(1, title)

   xSet <- data$Time
   xTitle <- "Time{t}[s]"
   xAxisTicks <- getUsefulTimeRange(xSet)
   # xAxisTicks <- seq(0,5,1)

   ySet <- data$Value * 1000.0
   yTitle <- paste(sep="", outputName, "[ms]")
   yAxisTicks <- getUsefulTicks(ySet)
   # yAxisTicks <- seq(0, 1000, 100)

   zSet <- data$Split  ; zTitle <- "Path{:psi:}"
   vSet <- data$Vector ; vTitle <- "Vector{:nu:}"
   wSet <- c() ; wTitle <- ""
   aSet <- c() ; aTitle <- "" ; bSet <- c() ; bTitle <- ""
   pSet <- data$Object ; pTitle <- "Object{:Omega:}"

   zColorArray    <- rainbow2(3)
   dotScaleFactor <- 1.25
   legendPos      <- c(0.5,1)   # Legend position (0,0) to (1,1)

   plotstd6(title,
            pTitle, aTitle, bTitle, xTitle, yTitle, zTitle,
            pSet, aSet, bSet, xSet, ySet, zSet,
            vSet, wSet, vTitle, wTitle,
            xAxisTicks=xAxisTicks,
            yAxisTicks=yAxisTicks,
            dotScaleFactor=dotScaleFactor,
            type="stepsx",
            colorMode=cmColor,
            zColorArray=zColorArray,
            hideLegend=FALSE,
            legendPos=legendPos)
}


# ###### Plot TSNs ##########################################################
plotTSNs <- function(data, outputName)
{
   title  <- outputName
   addBookmarkInPDFMetadata(1, title)

   xSet <- data$Time
   if(length(xSet) < 1) {
      cat(sep="", "NOTE: Skipping ", outputName, ": no data to plot!\n")
      return(FALSE)
   }
   xTitle <- "Time{t}[s]"
   xAxisTicks <- getUsefulTimeRange(xSet)
   # xAxisTicks <- seq(0,5,1)

   ySet <- data$Value
   yTitle <- outputName
   yAxisTicks <- getUsefulTicks(ySet)
   # yAxisTicks <- seq(0, 1000, 100)

   zSet <- data$Split  ; zTitle <- "Path{:psi:}"
   vSet <- data$Vector ; vTitle <- "Vector{:nu:}"
   wSet <- c() ; wTitle <- ""
   aSet <- c() ; aTitle <- "" ; bSet <- c() ; bTitle <- ""
   pSet <- data$Object ; pTitle <- "Object{:Omega:}"

   zColorArray    <- rainbow2(3)
   dotScaleFactor <- 1.25
   legendPos      <- c(0.5,1)   # Legend position (0,0) to (1,1)

   plotstd6(title,
            pTitle, aTitle, bTitle, xTitle, yTitle, zTitle,
            pSet, aSet, bSet, xSet, ySet, zSet,
            vSet, wSet, vTitle, wTitle,
            xAxisTicks=xAxisTicks,
            yAxisTicks=yAxisTicks,
            type="stepsx",
            dotScaleFactor=dotScaleFactor,
            colorMode=cmColor,
            zColorArray=zColorArray,
            hideLegend=FALSE,
            legendPos=legendPos)
}



source("experiments/tools/plotter.R")

width  <- 40
height <- 30


data <- loadResults("cc.data")

# ---- Time Range Filter ----
# data <- subset(data, ((data$Time >= 17) & (data$Time <= 23)))


sdata <- subset(data, grepl("server", data$Object))   # --- Plot only client side ---
cdata <- subset(data, grepl("client", data$Object))   # --- Plot only client side ---

pdf("cc.pdf", width=width, height=height, family="Helvetica", pointsize=24)
# png("cc%02d.png", type="cairo", width=72*width, height=72*height, pointsize=22)
openPDFMetadata("cc")

plotCwndAndSST( subset(cdata, grepl("Congestion Window", cdata$Vector) | grepl("Slow Start Threshold", cdata$Vector)), "Congestion Window and Slow Start Threshold" )
plotCwndAndSST( subset(cdata, grepl("Partial Bytes Acked", cdata$Vector)), "Partial Bytes Acked" )
plotCwndAndSST( subset(cdata, grepl("Fast Recovery State", cdata$Vector)), "Fast Recovery Status" )
plotCwndAndSST( subset(sdata, grepl("Advertised Receiver Window", sdata$Vector)), "Advertised Receiver Window")

plotCwndAndSST( subset(cdata, grepl("Outstanding Bytes", cdata$Vector)), "Outstanding Bytes", "Outstanding Bytes [Bytes]" )
plotCwndAndSST( subset(cdata, grepl("Queued Sent Bytes", cdata$Vector)), "Queued Sent Bytes", "Queue Size [Bytes]" )
plotCwndAndSST( subset(sdata, grepl("Queued Received Bytes", sdata$Vector)), "Queued Received Bytes", "Queue Size [Bytes]" )


blockingFraction <- subset(cdata, grepl("Sender Blocking Fraction", cdata$Vector))
if(length(blockingFraction) > 1) {
   plotCwndAndSST( blockingFraction, "Path Sender Blocking Fraction", "Blocking Fraction" )
}
blockingFraction <- subset(cdata, grepl("Receiver Blocking Fraction", cdata$Vector))
if(length(blockingFraction) > 1) {
   plotCwndAndSST( blockingFraction, "Path Receiver Blocking Fraction", "Blocking Fraction" )
}


plotRTTorRTO( subset(cdata, grepl("RTT", cdata$Vector)), "Round Trip Time (RTT)" )
plotRTTorRTO( subset(cdata, grepl("RTO", cdata$Vector)), "Retransmission Timeout (RTO)" )


plotTSNs( subset(cdata, grepl("TSN Sent", cdata$Vector)), "TSN Sent" )
blockingTSNsMoved <- subset(cdata, grepl("Blocking TSNs Moved", cdata$Vector))
if(length(blockingTSNsMoved) > 1) {
   plotTSNs( blockingTSNsMoved, "Blocking TSNs Moved" )
}

plotTSNs( subset(sdata, grepl("TSN Received", sdata$Vector)), "TSN Received" )
plotTSNs( subset(cdata, grepl("TSN Acked", cdata$Vector)), "TSN Acknowledged" )
pseudoCumAck <- subset(cdata, grepl("TSN PseudoCumAck", cdata$Vector) | grepl("TSN RTXPseudoCumAck", cdata$Vector) | grepl("TSN Acked CumAck", cdata$Vector))
if(length(pseudoCumAck) > 0) {
   plotTSNs( pseudoCumAck, "CMT PseudoCumAck" )
}

# plotGapInfo( subset(cdata, grepl("Number of Gap Blocks", cdata$Vector)), "Number of Gap Blocks in Last SACK" )
# plotGapInfo( subset(cdata, grepl("Number of Gap Acks", cdata$Vector)), "Number of Gap Acks in Last SACK" )
# plotGapInfo( subset(cdata, grepl("Number of Gap Missings", cdata$Vector)), "Number of Gap Missings in Last SACK" )

closePDFMetadata()
dev.off()
