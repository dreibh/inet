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
plotCwnd <- function(data, outputName, yTitle="Window Size [Bytes]")
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

source("experiments/tools/plotter.R")

width  <- 40
height <- 30


data <- loadResults("cc.data")

# ---- Time Range Filter ----
# data <- subset(data, ((data$Time >= 17) & (data$Time <= 23)))


sdata <- subset(data, grepl("server", data$Object))   # --- Plot only client side ---
cdata <- subset(data, grepl("client", data$Object))   # --- Plot only client side ---

pdf("cc.pdf", width=width, height=height, family="Helvetica", pointsize=40)
# png("cc%02d.png", type="cairo", width=72*width, height=72*height, pointsize=22)
openPDFMetadata("cc")

## Plot CWND
plotCwnd( subset(cdata, grepl("[subflow][cwnd]", cdata$Vector)), "TCP Congestion Window" )
## Plot RTT
plotRTTorRTO( subset(cdata, grepl("[subflow][measured RTT]", cdata$Vector)), "Round Trip Time (RTT)" )
## Plot RTO
# PROBLEM plotRTTorRTO( subset(cdata, grepl("[subflow][RTO]", cdata$Vector)), "Retransmission Timeout (RTO)" )

closePDFMetadata()
dev.off()
